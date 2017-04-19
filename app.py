from flask import Flask, render_template, request, session, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from rauth.service import OAuth1Service
from rauth.utils import parse_utf8_qsl
from os import environ
from datetime import datetime, date
import re

app = Flask(__name__)

app.config.update(
    APPLICATON_ROOT='/remember_prayers',
    SECRET_KEY=bytes.fromhex(environ['RP_SESSION_KEY']),
    SQLALCHEMY_DATABASE_URI='sqlite:///test.db',
    DEBUG=True
)

db = SQLAlchemy(app)

twitter = OAuth1Service(
    name='twitter',
    consumer_key=environ['RP_CONSUMER_KEY'],
    consumer_secret=environ['RP_CONSUMER_SECRET'],
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize'
)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))

    def __init__(self, twitter_id, name):
        self.user_id = user_id
        self.name = name

    def __repr__(self):
        return '<User %r>' % self.name

class Company(db.Model):
    __tablename__ = 'companies'
    company_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Company %r>' % self.name

class Pray(db.Model):
    __tablename__ = 'pray'
    pray_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    company_id = db.Column(db.Integer)
    date = db.Column(db.Date)

    def __init__(self, user_id, company_id, date):
        self.user_id = user_id
        self.company_id = company_id
        self.date = date

    def __repr__(self):
        return '<Pray from %r to %r>' % (self.company_id, self.user_id)

def auth_render_template(html_path):
    if 'id' in session:
        return render_template(html_path)
    else:
        return redirect(url_for('login'))
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    oauth_callback = url_for('authorized', _external=True)
    params = {'oauth_callback': oauth_callback}

    r = twitter.get_raw_request_token(params=params)
    data = parse_utf8_qsl(r.content)

    session['twitter_oauth'] = (data['oauth_token'], data['oauth_token_secret'])
    return redirect(twitter.get_authorize_url(data['oauth_token'], **params))

@app.route('/authorized')
def authorized():
    request_token, request_token_secret = session.pop('twitter_oauth')

    if not 'oauth_token' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))
    try:
        creds = {
                'request_token': request_token,
                'request_token_secret': request_token_secret
                }
        params = {'oauth_verifier': request.args['oauth_verifier']}
        sess = twitter.get_auth_session(params=params, **creds)
    except Exception as e:
        flash('There was a problem logging into Twitter: ' + str(e))
        return redirect(url_for('index'))

    verify = sess.get('account/verify_credentials.json',
                    params={'format':'json'}).json()

    session['username'] = verify['screen_name']
    session['id'] = verify['id']

    flash('Logged in as ' + verify['name'])
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('id', None)
    return redirect(url_for('index'))

@app.route('/mypage')
def mypage():
    if 'id' in session:
        pray_list = Pray.query.filter_by(user_id = session['id']).join(Company, Pray.company_id==Company.company_id).add_columns(Company.name, Pray.date).all()
        print(pray_list)
        return render_template('mypage.html', pray_list=pray_list)
    else:
        return redirect(url_for('login'))

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'id' in session and request.method == 'POST'\
        and 'prayer' in request.form and 'date' in request.form:
        prayer = request.form['prayer']
        datestr = request.form['date']

        # date validation check
        if re.compile('\A\d{4}/\d{2}/\d{2}\Z').match(datestr) is None:
            flash('Invalid date format')
            return redirect(url_for('index'))

        # company already exists?
        company = Company.query.filter_by(name=prayer).first()
        if company is None:
            # not exists -> insert
            c = Company(prayer)
            db.session.add(c)
            db.session.commit()
            company_id = c.company_id
        else:
            company_id = company.company_id

        d = datetime.strptime(datestr, '%Y/%m/%d').date()
        pray = Pray(session['id'], company_id, d)
        db.session.add(pray)
        db.session.commit()

    return auth_render_template('submit.html')

@app.route('/ranking')
def ranking():
    return render_template('ranking.html')

if __name__ == '__main__':
    app.run()
