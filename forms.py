from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, TextAreaField, IntegerField, BooleanField,
                     SubmitField, FloatField, SelectField)

from wtforms.validators import (DataRequired, Regexp, ValidationError, Email,
                                Length, EqualTo)

from models import User


def name_exists(form, field):
    if User.select().where(User.username == field.data).exists():
        raise ValidationError('User with that name exists.')


def email_exists(form, field):
    if User.select().where(User.email == field.data).exists():
        raise ValidationError('User with that email exists.')


class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Regexp(
                r'^[a-zA-Z0-9_]+$',
                message=("Username should be one word, letters, numbers,"
                         "and underscores only.")

            ),
            name_exists
        ])
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(),
            email_exists
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=2),
            EqualTo('password2', message='Passwords must match')
        ]
    )

    password2 = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired()
        ]
    )


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class PostForm(FlaskForm):
    email = TextAreaField("Email", validators = [DataRequired()])
    content = TextAreaField("Address", validators = [DataRequired()])


class EtherForm(FlaskForm):
    amount = IntegerField("Amount", validators = [DataRequired()])


class IconForm(FlaskForm):
    amount = IntegerField("Amount", validators = [DataRequired()])


class CoinForm(FlaskForm):
    addr = StringField("My Address", validators=[DataRequired()])
    coin = FloatField("Coin", validators=[DataRequired()])
    sele = SelectField(
        'Type',
        choices=[('eth', 'Ethereum'), ('icx', 'ICON')]
    )
    btns = SubmitField("To")

class QuestionForm(FlaskForm):
    question = StringField(
        'Question',
        validators=[
            DataRequired(),
            name_exists
        ])

