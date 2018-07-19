from flask import Flask, render_template, redirect, request, session, flash
import re
app = Flask(__name__)
from flask_bcrypt import Bcrypt 
from mysqlconnection import connectToMySQL
app.secret_key = "helloworld"
mysql = connectToMySQL("loginreg")
bcrypt = Bcrypt(app) 



@app.route('/')
def index():
    # identify whether the user has a session with us
    if 'userid' not in session:
        session['userid'] = False 

    return render_template("index.html")

@app.route('/submit', methods= ['post'])
def result():
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    print("in the submit")
    passFlag = True
    if len(request.form['first_name']) < 1:
        flash('Invalid first name!', 'wrong')
        passFlag = False
    elif not request.form['first_name'].isalpha():
        flash('First name invalid')
        passFlag = False
    if len(request.form['last_name']) < 1:
        flash('Invalid last name', 'wrong')
        passFlag = False
    elif not request.form['last_name'].isalpha():
        flash('Invalid last name', 'wrong')
        passFlag = False
    if len(request.form['email']) < 1:
        flash('Invalid email', 'wrong')
        passFlag = False
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email format!', 'wrong')
        passFlag = False
    else: #checking for duplicates
        query = "SELECT * FROM users WHERE email = %(user_email)s;" #does this email exist 
        data = { "user_email" : request.form['email'] }
        print(request.form['email'])
        emails = mysql.query_db(query, data) 
        print("here's what we got back from the database", len(emails))
        if len(emails) > 0:
            passFlag = False  
            flash("Email already exists!", "wrong")
    
    if len(request.form['password']) < 8:
        flash('Password must contain at least 8 characters!', 'wrong')
        passFlag = False
    if request.form['password'] != request.form['confirm_password']:
        flash('Password does not match!', 'wrong')
        passFlag = False

    if passFlag == True:
        flash('Success!', 'success') #save person in database
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print(pw_hash)  
        query = "INSERT INTO users (first_name, last_name, email, hash, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s,%(email)s, %(hash)s, NOW(), NOW());"
    # put the pw_hash in our data dictionary, NOT the password the user provided
        data = { 
                'first_name': request.form['first_name'],
                'last_name': request.form['last_name'],
                'email': request.form['email'],
                'hash': pw_hash
                }
        red = mysql.query_db(query, data)
        session['userid'] = red
        return redirect('/success')
    # never render on a post, always redirect!
    return redirect('/')

@app.route('/success')
def success():
    if 'userid' in session and session['userid'] != False:
        print("IN session!!!!")
        return render_template("success.html")
    else:
        print("not in session, not allowed")
        return redirect('/')


@app.route("/logout")
def logout():
    session.clear()
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    query = "SELECT * FROM users WHERE email = %(user_email)s;" #does this email exist 
    data = { "user_email" : request.form['email'] }
    print(request.form['email'])
    result = mysql.query_db(query, data)# see if the username provided exists in the databasecopy
    if result: #checking preventing duplicates
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['hash'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session['userid'] = result[0]['id']
            # never render on a post, always redirect!
            return redirect('/success')
    flash("You could not be logged in")
    return redirect("/")

    
if __name__ == "__main__":
    app.run(debug=True)