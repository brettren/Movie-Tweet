#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac  # Keyed-Hashing for Message Authentication
import logging
import json
from string import letters
import urllib2
from xml.dom import minidom
from google.appengine.api import urlfetch

import webapp2
import jinja2
import HTMLParser
from google.appengine.ext import db

import sys

reload(sys)
sys.setdefaultencoding("utf-8")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart' # used to check cookie

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)  # string of html

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest()) # Cookie Hashing

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]  # get original value
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d) # convert object(list) into JSON
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):  # when login
        cookie_val = make_secure_val(val)  # val|cookie, use user id to generate cookie
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))  # 'user_id' = cookie

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name) # val|hash
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id())) # every user object has a unique id

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw): # Initializes the handler instance with Request and Response objects
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class MainPage(BlogHandler):
  	def get(self):
  		ip = self.request.remote_addr
  		lon, lat, addr, country = get_coords(self.request.remote_addr)
  		img_url = gmap_img(lon, lat)
  		img_icon, description, temp_min, temp_max, pressure, humidity = get_weather(lon, lat)
	 	self.render('mainpage.html', ip = ip, location = addr, country = country, img_url = img_url,
	 				img_icon = img_icon, temp_max = temp_max, pressure = pressure, humidity = humidity)


# get ip of client
IP_URL = "https://freegeoip.net/json/"

def get_coords(ip):

    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content: # content is not None
        json_txt = json.loads(content)
        lon = json_txt["longitude"]
        lat = json_txt["latitude"]
        addr = json_txt["city"]
        country = json_txt["country_name"]
        return lon, lat, addr, country


# get the static google map
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&zoom=10&"
def gmap_img(lon, lat):
    markers = 'markers=%s,%s' % (lat, lon)
    return GMAPS_URL + markers

# get the weather json
WEATHER_URL = "http://api.openweathermap.org/data/2.5/weather?"
def get_weather(lon, lat):
	coords = "lat=%s&lon=%s" % (lat, lon)
	url = WEATHER_URL + coords
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return

	if content:
		json_txt = json.loads(content)
		weather = json_txt["weather"]
		weather_icon = weather[0]["icon"]
		img_icon = "http://openweathermap.org/img/w/%s.png" % weather_icon
		description = weather[0]["main"]
		main = json_txt["main"]
		temp_min = int(round(main["temp_min"] - 273.15))
		temp_max = int(round(main["temp_max"] - 273.15))
		pressure = main["pressure"]
		humidity = main["humidity"]
	return img_icon, description, temp_min, temp_max, pressure, humidity


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()  # generate random string of length 5
    h = hashlib.sha256(name + pw + salt).hexdigest() # use the name+pw+salt to generate hashcode as pw hashing
    return '%s,%s' % (salt, h)  # return salt,hashcode, every entity has a different random salt

def valid_pw(name, password, h):  # input pw, hashpw in database
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()  # all() Returns a Query object that represents all entities for the kind corresponding to this model
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)   # return salt,hash
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):  
        u = cls.by_name(name)  # return the user object according to the name, name is unique
        if u and valid_pw(name, pw, u.pw_hash):  # check pw
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)  # render the new page

    def as_dict(self):
        time_fmt = '%c' # Locales time
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),  # Return a string representing the date
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class BlogFront(BlogHandler):  # render all post
    def get(self):
        posts = greetings = Post.all().order('-created')  # descending order   return all posts
        if self.format == 'html':
			self.render('front.html', posts = posts)
        else:
            return self.render_json([p.as_dict() for p in posts])

    def post(self):
    	query = self.request.get('query')
    	query = query.replace(" ", "%20") 	
    	if query:
	    	self.redirect('/search?q=' + query)



class PostPage(BlogHandler):  # render one post
    def get(self, post_id): # An instance of the Key class represents a unique key for a Datastore entity
        key = db.Key.from_path('Post', int(post_id), parent=blog_key()) # Builds a new Key object
        post = db.get(key)  # Fetch the specific Model instance(s) with the given key(s) from the Datastore

        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("permalink.html", post = post)
        else:
            self.render_json(post.as_dict())

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user = self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))  # the id of object is automatically created, Returns the numeric ID of the data entity
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)  # keep the input info


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')  # parse request form
        password = self.request.get('password')

        u = User.login(username, password)  # return the user object
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

class History(BlogHandler):
	def get(self):
		posts = greetings = Post.all().order('-created').filter("user =", self.user.name) 
		self.render('history.html', posts = posts)

# get the search result
class SearchResult(BlogHandler):
	def get(self):
		urlfetch.set_default_fetch_deadline(60)
		q = self.request.get('q')
		query = q.replace(" ", "%20") 
		movies, count = getMovieList(query)
		print(movies)
		self.render('test.html', movies = movies, query = q, count = count)

SEARCH_URL = "http://www.imdb.com/search/title?title=%s&title_type=feature,tv_series,game"
def getMovieList(query):
	page = urllib2.urlopen(SEARCH_URL % query).read()
	movies = []
	start_index = page.find("<tr class")

	while start_index != -1:
		movie = {}

		href_index = page.find("<a href=", start_index)
		start_quote = page.find('"', href_index)
		end_quote = page.find('"', start_quote + 1)
		url = page[start_quote + 1:end_quote]

		movie['url'] = url

		title_index = page.find("title=", end_quote)
		start_quote = page.find('"', title_index)
		end_quote = page.find('(', start_quote + 1)
		title = page[start_quote + 1:end_quote]

		movie['title'] = HTMLParser.HTMLParser().unescape(title)

		year = page[end_quote + 1:end_quote + 5]

		movie['year'] = year

		img_index = page.find("img src=", end_quote)
		start_quote = page.find('"', img_index)
		end_quote = page.find('"', start_quote + 1)
		img_url = page[start_quote + 1:end_quote]

		movie['img_url'] = img_url

		rating_index = page.find("rated this ", end_quote)
		rating = page[rating_index + 11:rating_index + 14]

		movie['rating'] = rating

		outline_index = page.find("class=\"outline\">", rating_index)
		start_quote = page.find('>', outline_index)
		end_quote = page.find('<', start_quote + 1)
		outline = page[start_quote + 1:end_quote]

		movie['outline'] = outline

		dir_index = page.find("Dir: <a href=", rating_index)
		start_quote = page.find('>', dir_index)
		end_quote = page.find('<', start_quote + 1)
		director = page[start_quote + 1:end_quote]

		movie['director'] = director

		movies.append(movie)

		if len(movies)== 50:
			break

		start_index = page.find("<tr class", end_quote)

	return movies, len(movies)

# get the detailed info
# DETAIL_URL = "http://www.omdbapi.com/?i=%s&plot=full&r=json"
# class DetailedResult(BlogHandler):
# 	def get(self):
# 		ID = self.request.get('i')
# 		content = urllib2.urlopen(DETAIL_URL % ID).read()
# 		r = json.loads(content)
# 		self.render('detailed.html', r = r)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?(?:.json)?', BlogFront),
                               ('/blog/([0-9]+)(?:.json)?', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/history', History),
                               ('/search', SearchResult)
                               ],
                              debug=True)




















