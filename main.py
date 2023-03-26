from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Gravatar implementation
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# #CONFIGURE TABLES

# Table that holds all User objects
class User(UserMixin, db.Model):
    # parent table
    __tablename__ = "users"
    # The UserMixin inherited to get the flask-login properties
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    # --------Parent relationships--------- (Each User will have many BlogPost)
    # "posts" is like a list of blogpost objects attached to each user
    # "author" refer to the "author" attribute of the BlogPost class
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


# Table that  holds all BlogPost objects of a user
class BlogPost(db.Model):
    # child table
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ------- Parent relationships -------(Each BlogPost will have many Comment)
        # With Comment object
    comments = relationship("Comment", back_populates="parent_post")

    # ==== Child relationships =====-#
        # With User object
    # the foreignkey "users.id" refers to the table name of the user
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # referencing the User object. "posts" refers to the "posts" attribute in the User class
    author = relationship("User", back_populates="posts")



# Table that holds all the Comments of users
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # The "text" property will contain the text entered in the CKEditor
    text = db.Column(db.Text, nullable=False)

    # -----Child relationships-------#
        # With User object
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
        # With BlogPost object
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")




db.create_all()


# Create admin-only decorator
def admin_only(function):
    # wraps() copies the inherits the original function information to the new function
    @wraps(function)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        try:
            if current_user.id != 1:
                return abort(403)
            # Otherwise continue with the route function
            return function(*args, **kwargs)

        # if no one has logged in yet, return 403 Error
        except AttributeError:
            return abort(403)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    # Add new user object to the database
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        # check if user already exists
        if User.query.filter_by(email=register_form.email.data).first():
            flash("User already exists. Please Login!")
            return redirect(url_for("login"))

        new_user = User(
            name=register_form.name.data,
            email=register_form.email.data,
            password=generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256", salt_length=8),
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=register_form)


# Flask-login setup
login_manager = LoginManager()
login_manager.init_app(app)


# defining load user function (this loads the user in the session)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        query_email = login_form.email.data
        query_password = login_form.password.data
        user = User.query.filter_by(email=query_email).first()
        # checking if the user exists
        if not user:
            flash("Not a registered user. Please try again or Sign-up to register.")
            return redirect(url_for('login'))
        elif not check_password_hash(pwhash=user.password, password=query_password):
            flash("Password Incorrect. Please Try Again!")
            return redirect(url_for('login'))
        else:
            # if user exists and password matches, authenticate the user and log-in
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    # saving the comments in Comments table (only- logged-in users can submit comments)
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment_form.comment.data,
                comment_author=current_user,
                parent_post=requested_post,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            flash("You need to be a logged-in user to comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(port=5001, debug=True)
