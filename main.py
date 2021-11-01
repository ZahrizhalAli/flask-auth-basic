from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CHEAT_SHEET'] = 'static'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('secrets'))
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('secrets'))
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash('User already registered.')
            return redirect(url_for('login'))
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=request.form['email'], password=hashed_password, name=request.form['name'])
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect('secrets')
    return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('secrets'))
    if request.method == 'POST':
        get_user = User.query.filter_by(email=request.form.get('email')).first()
        if get_user:
            user_pass = get_user.password
            check = check_password_hash(user_pass, request.form.get('password'))
            if check:
                user_pass = ""
                login_user(get_user)
                return redirect(url_for("secrets"))
            else:
                flash("Password wrong.")
                return redirect(url_for("login"))
        else:
            flash("User not found. Please register first.")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(app.config['CHEAT_SHEET'], filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
