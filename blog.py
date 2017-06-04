import os
import re
import random
import hashlib
import hmac
import time
from string import letters
import webapp2
import jinja2
import logging
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

secret = 'N0rmand1a!.'

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		"""
		Write the output to the browser
		"""
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		"""
		Renders html template
		"""
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		"""
		Set secure cookie
		"""
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		"""
		Read cookie from browser
		"""
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		"""
		Check User
		"""
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		"""
		Remove login information
		"""
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

#Main Function
class MainPage(BlogHandler):
	def get(self):
		posts = Post.all().order('-created')
		self.render('front.html', posts = posts)


def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	"""
    Stores user information
    """
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		"""
        Returns user id from User object
        """
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		"""
        Fetchs users by name from the User object
        """
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		"""
        Creates the new user in the User object.
        """
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		"""
		Login method
		"""
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


##### blog stuff

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	"""
	post datastore
	"""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	author = db.IntegerProperty(required = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)
	

#Like Model
class Like(db.Model):
	"""
	Like datastore
	"""
	authorLike = db.IntegerProperty(required = True)
	post = db.IntegerProperty(required = True)
	like = db.IntegerProperty()

#Comment Model
class Comment(db.Model):
	"""
	Comment datastore
	"""
	post = db.IntegerProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	author = db.IntegerProperty(required = True)

	@classmethod
	def by_post_id(cls, post_id):
		c = cls.all().filter('post =', int(post_id))
		return c

	@classmethod
	def by_id(cls, post_id):
		c = cls.all().filter('id() =', int(post_id))
		return c

class BlogFront(BlogHandler):
	def get(self):
		posts = Post.all().order('-created')
		self.render('front.html', posts = posts)

class PostPage(BlogHandler):
	def get(self, post_id):
		"""
        Renders Posts to home page
        """
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		comments = Comment.by_post_id(post_id)
				
		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post, comments=comments)

class NewPost(BlogHandler):
	"""
	Creates new posts
	"""
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			return self.redirect("/login")

	def post(self):
		if not self.user:
			return self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')
		author = self.user.key().id();

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content, author = author)
			p.put()
			time.sleep(0.1)
			
			posts = Post.all().order('-created')
			self.render('front.html', posts = posts)
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, content=content, error=error)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

#Signup Function
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
		raise NotImplementedError


class Register(Signup):
	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			return self.redirect('/blog')

#Login Function
class Login(BlogHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		
		u = User.login(username, password)
		if u:
			self.login(u)
			return self.redirect('/blog')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(BlogHandler):
	def get(self):
		self.logout()
		return self.redirect('/blog')

#Edit Post
class EditPost(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if self.user:
			if post.author != self.user.key().id():
				error = "You do not have permission to edit this post!"
				self.render("permalink.html", post = post, error=error)
			else:
				self.render("editpost.html", subject=post.subject, content=post.content)
		else:
			return self.redirect('/login')

	def post(self, post_id):
		if not self.user:
			return self.redirect('/login')

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if post is not None:
			userid = self.read_secure_cookie('user_id')
			subject = self.request.get('subject')
			content = self.request.get('content')

			if post.author != self.user.key().id():
				error = "You do not have permission to edit this post!"
				self.render("editpost.html", subject=subject, content=content, error=error)
			else:
				if subject and content:
					post.subject = subject
					post.content = content
					post.put()
					time.sleep(0.1)
					return self.redirect('/blog')
				else:
					error = "Please enter Subject and Content"
					self.render("editpost.html", subject=subject, content=content, error=error)

#Delete Post
class DeletePost(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		if post.author == self.user.key().id():
			if self.user:
				self.render("deletepost.html", post = post)
			else:
				return self.redirect('/login')
		else:
			error = "You do not have permission to delete this post!"
			self.render("permalink.html", post = post, error=error)

	def post(self, post_id):
		if not self.user:
			return self.redirect("/blog")
	
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		
		if post and (post.author == self.user.key().id()):
			post.delete()
			time.sleep(0.1)
		return self.redirect('/blog')

# Like Post
class LikePost(BlogHandler):
	def get(self, post_id):
		if not self.user:
			return self.redirect('/login')

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)	#aca tengo la info del creador del comentario

		if not post:
			self.error(404)
			return

		if post.author == self.user.key().id():
			error = "You can not like your own post!"
			self.render("permalink.html", post = post, error=error)
		else:
			like_obj = Like.all().filter("post =", int(post_id))
			#like_obj trae objetos de Like para analizar si ya likie ese comentario
			if like_obj:
				for obj in like_obj:
					if(obj.authorLike == self.user.key().id()):
						error = "You have liked this post!"
						self.render("permalink.html", post = post, error=error)
						return
				like_obj = Like(parent = blog_key(), authorLike=self.user.key().id(), post=post.key().id(), like=1)
				like_obj.put()
				return self.redirect('/')
			else:
				like_obj = Like(parent = blog_key(), authorLike=self.user.key().id(), post=post.key().id(), like=1)
				like_obj.put()
				return self.redirect('/')

# Comment
class CreateComment(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)	#aca tengo la info del creador del comentario

		subject = post.subject
		if self.user:
			self.render("comment.html", subject=subject)
		else:
			return self.redirect('/login')

	def post(self, post_id):
		if not self.user:
			return self.redirect('/login')

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)	#aca tengo la info del creador del comentario

		if not post:
			return self.redirect('/')

		content = self.request.get('content')
		if content:
			c = Comment(parent = blog_key(), post=post.key().id(), content=content, author=self.user.key().id())
			c.put()
			time.sleep(0.1)
			return self.redirect('/')
		else:
			error = "comment error"
			self.render("comment.html", error=error)

#Delete Comment
class DeleteComment(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
		comment = db.get(key)
		
		if not comment:
			self.error(404)
			return

		if comment.author == self.user.key().id():
			if self.user:
				self.render("deletecomment.html", comment = comment)

			else:
				return self.redirect('/login')
		else:
			error = "You can not delete this comment"
			self.render("deletecomment.html", error = error)

	def post(self, post_id):
		if not self.user:
			return self.redirect("/blog")
	
		key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
		comment = db.get(key)
		
		if comment and (comment.author == self.user.key().id()):
			comment.delete()
			time.sleep(0.1)
		return self.redirect('/blog')

#Edit Comment
class EditComment(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
		comment = db.get(key)

		if self.user:
			if comment.author != self.user.key().id():
				error = "You do not have permission to edit this comment!"
				self.render("editcomment.html", content=comment.content, error=error)
			else:
				self.render("editcomment.html", content=comment.content)
		else:
			return self.redirect('/login')

	def post(self, post_id):
		if not self.user:
			return self.redirect('/login')

		key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
		comment = db.get(key)
		
		content = self.request.get('content')

		if comment.author != self.user.key().id():
			error = "You do not have permission to edit this post!"
			self.render("editcomment.html", content=content, error=error)
		else:
			if content:
				comment.content = content
				comment.put()
				time.sleep(0.1)
				return self.redirect('/blog')
			else:
				error = "Please enter Content"
				self.render("editcomment.html", content=content, error=error)


app = webapp2.WSGIApplication([('/', MainPage),
							   ('/blog/?', BlogFront),
							   ('/blog/([0-9]+)', PostPage),
							   ('/blog/newpost', NewPost),
							   ('/blog/deletepost/([0-9]+)', DeletePost),
							   ('/blog/editpost/([0-9]+)', EditPost),
							   ('/blog/like/([0-9]+)', LikePost),
							   ('/blog/newcomment/([0-9]+)', CreateComment),
							   ('/blog/deletecomment/([0-9]+)', DeleteComment),
							   ('/blog/editcomment/([0-9]+)', EditComment),
							   ('/signup', Register),
							   ('/login', Login),
							   ('/logout', Logout),
							   ],
							  debug=True)
