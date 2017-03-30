from flask import Flask, render_template, request, session, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from rauth.service import OAuth1Service
from rauth.utils import parse_utf8_qsl
from os import environ

app = Flask(__name__)

app.config.update(
    APPLICATON_ROOT='/remember_prayers',
    SECRET_KEY=bytes.fromhex(environ['RP_SESSION_KEY']),
    DEBUG = True
)

twitter = OAuth1Service(
    name='twitter',
    consumer_key=environ['RP_CONSUMER_KEY'],
    consumer_secret=environ['RP_CONSUMER_SECRET'],
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize'
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    oauth_callback = url_for('authorized', _external=True)
    params = {'oauth_callback': oauth_callback}

    r = twitter.get_raw_request_token(params=params)
    print(r)
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
        return render_template('mypage.html')
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()
