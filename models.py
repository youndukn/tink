import datetime

from flask_bcrypt import generate_password_hash
from flask_bcrypt import check_password_hash
from flask_login import UserMixin
from peewee import *

DATABASE = SqliteDatabase('social.db')


class User(UserMixin, Model):
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.datetime.now)
    is_admin = BooleanField(default=False)

    class Meta:
        database = DATABASE
        order_by = ('-joined_at', )

    def get_post(self):
        return Post.select().where(
            Post.user == self
        )

    def get_stream(self):
        return Post.select().where(
            (Post.user << self.following()) |
            (Post.user == self)
        )

    def get_friends(self):
        return

    def get_coin_stream(self):
        return Coin.select().where(
            (Coin.user == self)
        )

    def get_question(self):
        return Question.select().where(Question.votes >= 1)

    def get_question_stream(self):
        return Question.select().where(Question.votes >= 1)

    def answered(self):
        """The users that we are following"""
        return (
            User.select().join(
                Relationship, on=Relationship.to_user
            ).where(
                Relationship.from_user == self
            )
        )



    def following(self):
        """The users that we are following"""
        return (
            User.select().join(
                Relationship, on=Relationship.to_user
            ).where(
                Relationship.from_user == self
            )
        )

    def followers(self):
        """The users that we are following the current user"""
        return (
            User.select().join(
                Relationship, on=Relationship.from_user
            ).where(
                Relationship.to_user == self
            )
        )

    @classmethod
    def create_user(cls, username, email, password, admin=False):
        try:
            with DATABASE.transaction():
                cls.create(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    is_admin=admin
                )
        except IntegrityError:
            raise ValueError("User already exists")


class Post(Model):
    timestamp = DateTimeField(default=datetime.datetime.now)
    user = ForeignKeyField(
        model=User,
        related_name='posts'
    )
    content = TextField()

    class Meta:
        database = DATABASE
        order_by = ('-timestamp', )


class Coin(Model):
    timestamp = DateTimeField(default=datetime.datetime.now)
    user = ForeignKeyField(
        model=User,
        related_name='coins'
    )
    amount = IntegerField()

    class Meta:
        database = DATABASE
        order_by = ('-timestamp')


class Coin(Model):
    timestamp = DateTimeField(default=datetime.datetime.now)
    user = ForeignKeyField(
        model=User,
        related_name='coins'
    )
    amount = IntegerField()

    class Meta:
        database = DATABASE
        order_by = ('-timestamp')


class Question(Model):
    timestamp = DateTimeField(default=datetime.datetime.now)
    user = ForeignKeyField(
        model=User,
        related_name='qeustions'
    )
    question = TextField()
    vote = BooleanField()

    class Meta:
        database = DATABASE
        order_by = ('-votes')


class Answered(Model):
    from_user = ForeignKeyField(User, related_name="answered")
    to_question = ForeignKeyField(Question, related_name='related_to')

    class Meta:
        database = DATABASE
        indexes = (
            (('from_user', 'to_question'), True)
        )


class Relationship(Model):
    from_user = ForeignKeyField(User, related_name='relationships')
    to_user = ForeignKeyField(User, related_name='related_to')

    class Meta:
        database = DATABASE
        indexes = (
            (('from_user', 'to_user'), True)
        )

def initialized():
    DATABASE.connect()
    DATABASE.create_tables([User, Post, Coin, Question], safe=True)
    DATABASE.close()