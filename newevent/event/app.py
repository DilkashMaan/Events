from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField,DateTimeField
from wtforms.validators import DataRequired,Optional
import mysql.connector
import json
from datetime import timedelta
from flask_cors import CORS
import bcrypt
from flask import flash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'deadly'
csrf = CSRFProtect(app)

CORS(app)

@app.before_request
def check_login():
    if 'user_id' not in session and request.endpoint not in ['login', 'index', 'logout']:
        return redirect(url_for('login')) 

# Database Connection
def connect_to_db():
   return mysql.connector.connect(
        host='localhost',
        user='root',
        password='admin@123',
        database='ticketbot'
    )

class CreditCardForm(FlaskForm):
    cardNumber = StringField('Card Number', validators=[DataRequired()])
    expirationDate = StringField('Expiration Date', validators=[DataRequired()])
    cvv = StringField('CVV', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login')

class AccountForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class EventForm(FlaskForm):
    eventname = StringField('Event Name', validators=[DataRequired()])
    date_and_time = DateTimeField('Event Date & Time', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    alternative_names = StringField('Alternative Names', validators=[Optional()])
    need_to_buy = StringField('Need to Buy')
    tickets_per_account_user = StringField('Tickets per Account User', validators=[DataRequired()])
    accounts_to_buy_from = StringField('Accounts to Buy From')
    bought = StringField('Bought')
    is_active = StringField('Is Active')
    under_progress = StringField('Under Progress')
    section = StringField('Section')

# User Created
@app.route("/user", methods=['POST'])
@csrf.exempt  
def add_user():
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    data = request.get_json()

    if isinstance(data, list):
        for user in data:
            username = user.get("username")
            password = user.get("password")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            sql = "INSERT INTO users (username, password) VALUES (%s, %s)"
            val = (username, hashed_password)
            cursor.execute(sql, val)
    else:
        username = data.get("username")
        password = data.get("password")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        sql = "INSERT INTO users (username, password) VALUES (%s, %s)"
        val = (username, hashed_password)
        cursor.execute(sql, val)
    cursor.close()
    db_connection.commit()
    db_connection.close()

    return jsonify({"message": "User created successfully"}), 200

@app.route("/user/<int:id>", methods=['DELETE'])
def delete_user(id):
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    sql = "DELETE FROM users WHERE id=%s"
    cursor.execute(sql, (id,))
    db_connection.commit()
    cursor.close()
    db_connection.close()
    return jsonify({"message": "account Deleted Successfully"})


@app.route("/user",methods=['GET'])
def get_user():
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    results = cursor.fetchall()
    cursor.close()
    db_connection.close()
    return jsonify(results)
    

@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit(): 
        username = form.username.data
        password = form.password.data
        db_connection = connect_to_db()
        cursor = db_connection.cursor(dictionary=True)
        sql = "SELECT id, password FROM users WHERE username = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            flash("Login successful!", "success")
            print(f"Login successful for user: {username}")
            return redirect(url_for('cardss'))  
        else:
            flash("Invalid username or password", "danger")
            print(f"Invalid credentials for user: {username}")
    return render_template("index.html", form=form)  

@app.route("/delete_card", methods=['POST'])
def delete_card_post():
    card_id = request.form.get('card_id') 
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    sql = "DELETE FROM cards WHERE id=%s"
    cursor.execute(sql, (card_id,))
    db_connection.commit()
    cursor.close()
    db_connection.close()
    return redirect(url_for('cardss')) 


@app.route("/cards", methods=['GET'])
def get_cards():
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    sql = 'SELECT * FROM cards'
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db_connection.commit()
    db_connection.close()
    return jsonify({"status": 200, "data": results})

@app.route('/add_card', methods=['POST'])
def add_card():
    card_number = request.form.get('number')
    card_cvv = request.form.get('cvv')
    card_expiry = request.form.get('expiry')
    if not card_number or not card_cvv or not card_expiry:
        return jsonify({"error": "Missing required fields"}), 400
    try:
        db_connection = connect_to_db()
        cursor = db_connection.cursor()
        cursor.execute("""INSERT INTO cards (number, cvv, expiry) VALUES (%s, %s, %s)""",
                       (card_number, card_cvv, card_expiry))
        db_connection.commit()
        cursor.close()
        db_connection.close()
        flash("Card added successfully", "success")
        return redirect(url_for('cardss'))
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/update_card', methods=['POST'])
def update_card():
    card_id = request.form.get('card_id')
    card_number = request.form.get('number')
    card_cvv = request.form.get('cvv')
    card_expiry = request.form.get('expiry')
    if not card_id or not card_number or not card_cvv or not card_expiry:
        return jsonify({"error": "Missing required fields"}), 400
    try:
        db_connection = connect_to_db()
        cursor = db_connection.cursor()
        cursor.execute("""UPDATE cards SET number = %s, cvv = %s, expiry = %s WHERE id = %s""",
                       (card_number, card_cvv, card_expiry, card_id))
        db_connection.commit()
        cursor.close()
        db_connection.close()
        flash("Card updated successfully", "success")
        return redirect(url_for('cardss'))
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    


# Accounts api
@app.route("/accounts", methods=['POST'])
def add_account():
    cardname = request.form.get('email')
    cardnum = request.form.get('password')
    if not cardname or not cardnum:
        return jsonify({"error": "Missing required fields"}), 400
    try:
        db_connection = connect_to_db()
        cursor = db_connection.cursor()
        cursor.execute("INSERT INTO accounts (email, password) VALUES (%s, %s)", (cardname, cardnum))
        db_connection.commit()
        cursor.close()
        db_connection.close()
        return redirect(url_for('accounts'))
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/update_account', methods=['POST'])
def update_account():
    account_id = request.form.get('account_id')
    new_email = request.form.get('email')
    new_password = request.form.get('password')
    if not account_id or not new_email or not new_password:
        return jsonify({"error": "Missing required fields"}), 400
    try:
        db_connection = connect_to_db()
        cursor = db_connection.cursor()
        cursor.execute("""UPDATE accounts SET email = %s, password = %s WHERE id = %s""",
                       (new_email, new_password, account_id))
        db_connection.commit()
        cursor.close()
        db_connection.close()
        return redirect(url_for('accounts'))
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/accounts', methods=['GET'])
def get_accounts():
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM accounts")
    results = cursor.fetchall()
    cursor.close()
    db_connection.close()
    return jsonify(results)

@app.route("/delete_account_post", methods=['POST'])
def delete_account_post():
    account_id = request.form.get('account_id')   
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    sql = "DELETE FROM accounts WHERE id=%s"
    cursor.execute(sql, (account_id,))
    db_connection.commit()
    cursor.close()
    db_connection.close()
    return redirect(url_for('accounts'))


# events api
@app.route('/add_event', methods=['POST'])
def add_event():
    # Extract form data from the request
    event_name = request.form.get('eventname')
    date_and_time = request.form.get('date_and_time')
    alternative_names = request.form.get('alternative_names')
    need_to_buy = request.form.get('need_to_buy')
    tickets_per_account_user = request.form.get('tickets_per_account_user')
    accounts_to_buy_from = request.form.get('accounts_to_buy_from')
    bought = request.form.get('bought')
    is_active = 1 if request.form.get('is_active') == 'on' else 0
    under_progress = 1 if request.form.get('under_progress') == 'on' else 0
    section = request.form.get('section')

    # Check for missing required fields
    if not all([event_name, date_and_time, tickets_per_account_user]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Connect to the database
        db_connection = connect_to_db()
        cursor = db_connection.cursor()

        # Insert data into the database
        sql = """
            INSERT INTO events (
                eventname, `datetime_in_uk`, alternative_names, need_to_buy, 
                tikets_per_account, accounts_from, bought,  Isactive, 
                underprogress, section
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            event_name, date_and_time, alternative_names, need_to_buy,
            tickets_per_account_user, accounts_to_buy_from, bought, is_active,
            under_progress, section
        )
        cursor.execute(sql, values)
        db_connection.commit()

        cursor.close()
        db_connection.close()
        flash("Event added successfully", "success")
        return redirect(url_for('eventss'))
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    

@app.route('/update_event', methods=['POST'])
def update_event():
    # Extract form data from the request
    event_id = request.form.get('event_id')
    event_name = request.form.get('eventname')
    date_and_time = request.form.get('date_and_time')
    alternative_names = request.form.get('alternative_names')
    need_to_buy = request.form.get('need_to_buy')
    tickets_per_account_user = request.form.get('tickets_per_account_user')
    accounts_to_buy_from = request.form.get('accounts_to_buy_from')
    bought = request.form.get('bought')
    is_active = 1 if request.form.get('is_active') == 'on' else 0
    under_progress = 1 if request.form.get('under_progress') == 'on' else 0
    section = request.form.get('section')
    if not all([event_id, event_name, date_and_time, tickets_per_account_user]):
        return jsonify({"error": "Missing required fields"}), 400
    try:
        db_connection = connect_to_db()
        cursor = db_connection.cursor()
        sql = """
            UPDATE events
            SET
                eventname = %s, `datetime_in_uk` = %s, alternative_names = %s, 
                need_to_buy = %s, tikets_per_account = %s, accounts_from = %s, 
                bought = %s, Isactive = %s, underprogress = %s, section = %s
            WHERE id = %s
        """
        values = (
            event_name, date_and_time, alternative_names, need_to_buy,
            tickets_per_account_user, accounts_to_buy_from, bought, is_active,
            under_progress, section, event_id
        )
        cursor.execute(sql, values)
        db_connection.commit()
        cursor.close()
        db_connection.close()
        return redirect(url_for('eventss'))
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




@app.route("/events", methods=['GET'])
def get_events():
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    sql = 'SELECT * FROM events'
    cursor.execute(sql)
    results = cursor.fetchall()
    cursor.close()
    db_connection.commit()
    db_connection.close()
    return jsonify({"status": 200, "data": results})


@app.route("/delete_event_post", methods=['POST'])
def delete_event_post():
    event_id = request.form.get('event_id')   
    db_connection = connect_to_db()
    cursor = db_connection.cursor(dictionary=True)
    sql = "DELETE FROM events WHERE id=%s"
    cursor.execute(sql, (event_id,))
    db_connection.commit()
    cursor.close()
    db_connection.close()
    return redirect(url_for('eventss'))



@app.route("/")
def index():
    form = LoginForm()   
    return render_template("index.html", form=form)

@app.route("/cardss")
def cardss():
    form = CreditCardForm()
    response = get_cards()
    cards_data = response.get_json().get('data', [])
    return render_template("card.html",form=form, cards=cards_data)

@app.route("/accountslist")
def accounts():
    form = AccountForm() 
    response = get_accounts()  
    accounts_data = response.json  
    return render_template("accounts.html",form=form, accounts=accounts_data)

@app.route("/eventss")
def eventss():
    form=EventForm()
    response = get_events()
    events_data = response.json.get('data', [])
    return render_template("admin.html", form = form,events=events_data)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()   
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
