from flask import (Flask, g, render_template, flash, redirect, url_for, abort, request)
from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, login_user, logout_user, login_required,
                         current_user)
import forms
import models

DEBUG = True
PORT = 8000
HOST = '0.0.0.0'

app = Flask(__name__)
app.secret_key = 'helloworldasdklfjalksdjklasdjf'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.get(models.User.id == userid)
    except models.DoesNotExist:
        return None


@app.before_request
def before_request():
    """Connect to the database before each request."""
    g.db = models.DATABASE
    g.db.connect()
    g.user = current_user


@app.after_request
def after_request(response):
    g.db.close()
    return response


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        flash("Registered Complete!", "success")
        models.User.create_user(
            username = form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(models.User.email == form.email.data)
        except models.DoesNotExist:
            flash("Your email or password doesn't match", "error")
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You've been logged in!", "success")
                return redirect(url_for('index'))
            else:
                flash("Your email or password doesn't match", "error")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged Out Success", "success")
    return redirect(url_for('index'))


@app.route('/new_post', methods = ('GET', 'POST'))
@login_required
def post():
    form = forms.PostForm()
    if form.validate_on_submit():
        models.Post.create(
            user=g.user._get_current_object(),
            content = form.content.data.strip())
        flash("Message posted", "success")
        return redirect(url_for('index'))
    return render_template('post.html', form=form)


@app.route('/')
@login_required
def index():
    stream = models.Coin.select().order_by(models.Coin.timestamp.desc()).limit(4)
    return render_template('coin_stream.html', stream=stream)


@app.route('/question', methods=('GET', 'POST'))
@login_required
def question():
    form = forms.QuestionForm()
    if form.validate_on_submit():
        models.Question.create(
            user=g.user._get_current_object(),
            question = form.question.data,
            vote = 1)
        flash("Question Submitted", "success")
        return redirect(url_for('index'))
    stream = current_user.get_question_stream().limit(100)
    return render_template('question.html', form=form, stream=stream)


@app.route('/question_stream/<int:question_id>')
def view_question(question_id):
    question = models.Question.select().where(models.Question.id == question_id)
    if question.count() == 0:
        abort(404)
    return render_template('question_stream.html', stream=question)


@app.route('/admin', methods = ('GET', 'POST'))
@login_required
def admin():

    tinkAmount = 0.0
    ethereum = 0.0
    form = forms.CoinForm()

    if request.method == 'POST':
        if request.form['btn'] == "To":
            if form.eth.data:
                ethereum = form.eth.data
                tinkAmount = form.eth.data * 1230

            if form.icx.data:
                ethereum = form.icx.data / 22
                tinkAmount = ethereum * 1230

            return render_template('admin.html', form=form, tink=tinkAmount, eth=ethereum)
        elif request.form['btn'] == "Confirm Rate":
            if form.validate_on_submit():
                tinkAmount = form.eth.data * 1230
                icxAmount = form.eth.data / 10
                if form.icx.data:
                    tinkAmount = form.icx.data * 12300
                    icxAmount = form.icx.data

                models.Coin.create(
                    user=g.user._get_current_object(),
                    icx=icxAmount,
                    eth=form.eth.data,
                    tink=tinkAmount)

                flash("Coin Submitted", "success")
                return redirect(url_for('index'))

    return render_template('admin.html', form=form, tink=tinkAmount, eth=ethereum)


@app.route('/coin_send/<username>')
def coin_send(username=None):
    template = 'coin_stream.html'
    if username and username != current_user.username:
        try:
            user = models.User.select().where(models.User.username**username).get()
        except models.DoesNotExist:
            abort(404)
        else:
            stream=user.coins.limit(100)
        user = current_user
    if username:
        template = 'coin_stream.html'
    return render_template(template, stream=stream, user=user)


@app.route('/coin')
@app.route('/coin/<username>')
def coin(username=None):
    template = 'coin_stream.html'
    if current_user.is_admin and username != current_user.username:
        try:
            user = models.User.select().where(models.User.username**username).get()
        except models.DoesNotExist:
            abort(404)
        else:
            stream=user.coins.limit(4)
    else:
        stream = current_user.get_coin_stream().limit(4)
        user = current_user
    if username:
        template = 'coin_stream.html'
    return render_template(template, stream=stream, user=user)


@app.route('/coin/<int:coin_id>')
def view_coin(coin_id):
    coins = models.Coin.select().order_by(models.Coin.timestamp.desc()).where(models.Coin.id == coin_id)
    if coins.count() == 0:
        abort(404)
    return render_template('coin_stream.html', stream=coins)


@app.route('/stream')
@app.route('/stream/<username>')
def stream(username=None):
    template = 'stream.html'
    if username and username != current_user.username:
        try:
            user = models.User.select().where(models.User.username**username).get()
        except models.DoesNotExist:
            abort(404)
        else:
            stream = user.posts.limit(100)
    else:
        stream = current_user.get_stream().limit(100)
        user = current_user
    if username:
        template = 'user_stream.html'
    return render_template(template, stream=stream, user=user)


@app.route('/post/<int:post_id>')
def view_post(post_id):
    posts = models.Post.select().where(models.Post.id == post_id)
    if posts.count() == 0:
        abort(404)
    return render_template('stream.html', stream=posts)


@app.route('/vote/<question_id>')
@login_required
def vote(question_id):
    try:
        to_question = models.Question.get(models.Question.id**question_id)
    except models.DoesNotExist:
        abort(404)
    else:
        try:
            models.Voted.create(
                from_user = g.user._get_current_object(),
                to_question=to_question
            )
        except models.IntegrityError:
            pass
        else:
            flash("You are now voted {}".format(to_question.question), "success")
    return redirect(url_for('question', question=to_question.id))



@app.route('/follow/<username>')
@login_required
def follow(username):
    try:
        to_user = models.User.get(models.User.username**username)
    except models.DoesNotExist:
        abort(404)
    else:
        try:
            models.Relationship.create(
                from_user = g.user._get_current_object(),
                to_user=to_user
            )
        except models.IntegrityError:
            pass
        else:
            flash("You are now following {}".format(to_user.username), "success")
    return redirect(url_for('stream', username=to_user.username))


@app.route('/follow/<username>')
@login_required
def unfollow(username):
    try:
        to_user = models.User.get(models.User.username**username)
    except models.DoesNotExist:
        abort(404)
    else:
        try:
            models.Relationship.get(
                from_user = g.user._get_current_object(),
                to_user=to_user
            ).delete_instance()
        except models.IntegrityError:
            pass
        else:
            flash("You've unfollowed {}".format(to_user.username), "success")
    return redirect(url_for('stream', username=to_user.username))


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    models.initialized()
    try:
        models.User.create_user(
            username='youndukn',
            email='youndukn1@gmail.com',
            password='password',
            admin=True
        )
    except ValueError:
        pass
    app.run(debug=DEBUG, host=HOST, port=PORT)
