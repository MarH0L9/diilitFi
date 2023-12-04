from flask import Flask, g, render_template, request, jsonify, url_for, redirect, flash, session,  make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func, desc
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DecimalField, BooleanField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Length
from flask_migrate import Migrate
from decouple import config
from flask_mail import Mail, Message
from itsdangerous import SignatureExpired, BadTimeSignature, URLSafeTimedSerializer
from datetime import datetime
import logging
import bcrypt
from flask import current_app
from ntpath import normpath, join
from markupsafe import Markup
import json
from decimal import Decimal
from sqlalchemy import DECIMAL, or_
import pytz
from flask_wtf.csrf import CSRFProtect
import uuid

#from flask_babel import Babel, _

timezone_fi = pytz.timezone('Europe/Helsinki')
now_utc = datetime.utcnow()
now_fi = now_utc.replace(tzinfo=pytz.utc).astimezone(timezone_fi)

app = Flask(__name__, template_folder='templates')
#babel = Babel(app)
csrf = CSRFProtect(app)

#TRANSLATIONS
#app.config['BABEL_DEFAULT_LOCALE'] = 'fi'
#babel.init_app(app)

# App Configuration
import os
app.config.from_pyfile('config.py')
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{config('LOCAL_DB_USERNAME')}:{config('LOCAL_DB_PASSWORD')}@localhost/{config('LOCAL_DB_NAME')}"
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['MAIL_SERVER'] = config('MAIL_SERVER')
app.config['MAIL_PORT'] = config('MAIL_PORT', cast=int)
app.config['MAIL_USERNAME'] = config('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = config('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = config('MAIL_USE_TLS', cast=bool)
app.config['MAIL_USE_SSL'] = config('MAIL_USE_SSL', cast=bool)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#app.config['SESSION_PERMANENT'] = False
#app.config['PERMANENT_SESSION_LIFETIME'] = tim

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), default='user')
    votes = db.relationship('Vote', back_populates='user')

    

    def __init__(self, username, email, password):  # Agregamos email al constructor
        self.username = username
        self.email = email
        self.password = self.hash_password(password)

    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def __repr__(self):
        return f'<{self.username}>'
    
    def total_deals(self):
        # Puedes personalizar esta lógica según cómo estás almacenando los deals en tu modelo
        return Deal.query.filter_by(user=self).count()
    
class Deal(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    photos = db.Column(db.String(1000))  # Ruta o URL de la foto del producto
    title = db.Column(db.String(255), nullable=False)
    store = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    publish_date = db.Column(db.DateTime, default=now_fi)
    expiration_date = db.Column(db.Date, nullable=False)  # Combina expiration_date y end_date en un solo campo
    offer_link = db.Column(db.String(255), nullable=False)
    discount_code = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='deals')
    offer_price = db.Column(DECIMAL(10, 2), nullable=False)
    regular_price = db.Column(DECIMAL(10, 2), nullable=False)
    shipping_cost = db.Column(DECIMAL(10, 2), nullable=False)
    start_date = db.Column(db.Date)
    category = db.Column(db.String(255))
    images = db.relationship('Image', backref='deal', lazy=True)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    votes = db.relationship('Vote', back_populates='deal')
    finished = db.Column(db.Boolean, default=False)
    finish_date = db.Column(db.DateTime)
    checked = db.Column(db.String(10), default='No')
    
    
    

    def __repr__(self):
        return f'<Deal {self.title}>'
    
    def total_votes(self):
        upvotes_count = Vote.query.filter_by(deal_id=self.id, vote_type='upvote').count()
        downvotes_count = Vote.query.filter_by(deal_id=self.id, vote_type='downvote').count()
        return upvotes_count - downvotes_count
    
    def has_upvoted(self, user):
        return Vote.query.filter_by(user_id=user.id, deal_id=self.id, vote_type='upvote').first() is not None

    def has_downvoted(self, user):
        return Vote.query.filter_by(user_id=user.id, deal_id=self.id, vote_type='downvote').first() is not None
    
    def score(self):
        return self.upvotes - self.downvotes
    
    
    @classmethod
    def get_deal_by_id(cls, deal_id):
        return db.session.query(cls).get(deal_id)
    
    def end_deal(self):
        self.finished = True
        self.finish_date = datetime.utcnow()
        db.session.commit()

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deal_id = db.Column(db.Integer, db.ForeignKey('deal.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    deal_id = db.Column(db.Integer, db.ForeignKey('deal.id'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  # 'upvote' o 'downvote'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones
    user = db.relationship('User', back_populates='votes')
    deal = db.relationship('Deal', back_populates='votes')   


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=now_fi, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='comments')
    deal_id = db.Column(db.Integer, db.ForeignKey('deal.id'))
    deal = db.relationship('Deal', backref='comments')
    checked = db.Column(db.String(10), default='No')
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Vanha salasana', validators=[DataRequired()])
    new_password = PasswordField('Uusi salasana', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Uusi salasana uudestaan', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Muokkaa salasana')

class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Update Comment')


class RememberMeToken(db.Model):
    __tablename__ = 'remember_me_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))





# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(f'The username "{username.data}" is already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            link = Markup('<a href="/reset-password">Here</a>')
            message = f'That email is already registered. <br> Did you forget your password?<br><br> Click {link} to reset it.'
            raise ValidationError(message)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('muista_minut')    
    submit = SubmitField('Login')

class DealForm(FlaskForm):
    title = StringField('title', validators=[DataRequired()])
    description = TextAreaField('description', validators=[DataRequired()])
    offer_price = DecimalField('offer_price', validators=[DataRequired()])
    regular_price = DecimalField('regular_price', validators=[DataRequired()])
    store = StringField('store', validators=[DataRequired()])
    expiration_date = StringField('expiration_date', validators=[DataRequired()])
    discount_code = StringField('discount_code')
    shipping_cost = DecimalField('shipping_cost', validators=[DataRequired()])
    start_date = StringField('start_date')
    category = StringField('category', validators=[DataRequired()])
    submit = SubmitField('Update Deal')



#Routes  
@app.route('/')
def index():
    # Obtén el tipo de orden desde los parámetros de la consulta (default: 'newest')
    order_by = request.args.get('order_by', 'newest')

    # Determina la columna de orden según el tipo de orden especificado
    if order_by == 'popularity':
        order_column = (func.coalesce(Deal.upvotes, 0) - func.coalesce(Deal.downvotes, 0)).label('vote_difference')
    else:
        order_column = Deal.publish_date

    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Realiza la consulta ordenada y paginada
    if order_by == 'popularity':
        # Filtra por las ofertas más populares
        deals = Deal.query.order_by(order_column.desc()).paginate(page=page, per_page=per_page, error_out=False)
    else:
        # Filtra por las ofertas más recientes (por defecto)
        deals = Deal.query.order_by(order_column.desc()).paginate(page=page, per_page=per_page, error_out=False)

    image_paths = [deal.photos for deal in deals.items]
    
    return render_template('index.html', latest_deals=deals, image_paths=image_paths, json_module=json, order_by=order_by)


@app.route('/category/<category>')
def category(category):
    page = request.args.get('page', 1, type=int)
    deals_in_category = Deal.query.filter_by(category=category).order_by(Deal.publish_date.desc()).paginate(page=page, per_page=10)
    
    category_names = {
        'electronics': 'Elektroniikka',
        'gaming': 'Gaming',
        'clothing': 'Vaatteet ja Muoti',
        'home_garden': 'Koti',
        'travel': 'Matkailu',
        'food': 'Ruoka ja Elintarvikkeet',
        'vehicles': 'Autot ja Ajoneuvot',
        'cinema_books': 'Elokuvat ja Kirjat',
        'services': 'Palvelut',
        'course_education': 'Kurssit ja Koulutus',
    }

    return render_template('category.html', category=category, category_name=category_names.get(category, category), category_deals=deals_in_category)

@app.route('/view_deal/<int:deal_id>')
def view_deal(deal_id):
    # Search for the deal in the database using the deal_id
    deal = Deal.query.get(deal_id)

    if deal:
        user = db.session.get(User, deal.user_id)

        # Verifica si el deal ha terminado
        deal_finished = False
    if deal.finished == 1:
        deal_finished = True

        # If deal is found, render the view_deal.html template
        return render_template('view_deal.html', deal=deal, user=user, deal_finished=deal_finished)
    else:
        # If deal is not found, redirect to the index page and error message
        
        return render_template('view_deal.html', deal=deal, user=user)
    
@app.route('/add_comment/<int:deal_id>', methods=['POST'])
@login_required
def add_comment(deal_id):
    deal = Deal.query.get(deal_id)

    if deal:
        # Manejar la lógica del formulario de comentarios
        if request.method == 'POST' and 'comment_text' in request.form:
            comment_text = request.form['comment_text']
            
            if comment_text:
                # Crear un nuevo comentario
                new_comment = Comment(text=comment_text, user_id=current_user.id, deal_id=deal_id)
                db.session.add(new_comment)
                db.session.commit()
                flash('Kommentti on lisätty onnistuneesti!', 'success')

                # Puedes redirigir a la misma página después de agregar un comentario
                return redirect(url_for('view_deal', deal_id=deal.id))

    else:
        flash('Diilia ei löydy', 'error')

    return redirect(url_for('index'))

@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Verify if the current user is the owner of the comment
    if current_user != comment.user:
        flash('You do not have permission to edit this comment.', 'danger')
        return redirect(url_for('index'))

    form = CommentForm()

    if form.validate_on_submit():
        comment.text = form.text.data
        db.session.commit()
        flash('Comment updated successfully!', 'success')
        return redirect(url_for('view_deal', deal_id=comment.deal.id))

    elif request.method == 'GET':
        form.text.data = comment.text

    return render_template('edit_comment.html', form=form, comment=comment)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Verify if the current user is the owner of the comment
    if current_user != comment.user:
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(url_for('index'))

    db.session.delete(comment)
    db.session.commit()

    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('view_deal', deal_id=comment.deal.id))



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password.data) 
        db.session.add(user)
        db.session.commit()

        # Generate token
        token = s.dumps(user.email, salt='email-confirm')

        # Create confirmation link
        confirm_url = url_for('confirm_email', token=token, _external=True)
        
        # Send email
        msg = Message('Confirm Your Email', sender='e67127609745a1@inbox.mailtrap.io', recipients=['e67127609745a1@inbox.mailtrap.io'])
        msg.html = f'''
        <p>Tervetuloa {user.username}!</p>
        <p>Vahvista sähköpostiosoitteesi klikkaamalla alla olevaa painiketta:</p>
        <a href="{confirm_url}" style="background-color: #007BFF; color: white; padding: 10px 15px; text-align: center; text-decoration: none; display: inline-block;">Vahvista Sähköposti</a>
        '''
        mail.send(msg)
        
        flash('Vahvistussähköposti on lähetetty sähköpostiosoitteeseesi..', 'info')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# Esta ruta manejará la verificación de nombre de usuario y correo electrónico
from flask import jsonify

from flask import jsonify

@app.route('/check-username-email', methods=['POST'])
def check_availability():
    try:
        print("Received POST request to /check-username-email")

        data = request.get_json()
        print("Received JSON data:", data)

        username = data.get('username')
        email = data.get('email')

        print("Received username:", username)
        print("Received email:", email)

        # Tarkista, onko käyttäjänimi jo olemassa
        user_exists = User.query.filter(User.username.ilike(username)).first()

        # Tarkista, onko sähköpostiosoite jo olemassa
        email_exists = User.query.filter(User.email.ilike(email)).first()

        response_data = {
            'usernameAvailable': not user_exists,
            'emailAvailable': not email_exists
        }

        print("Response data:", response_data)

        return jsonify(response_data)

    except Exception as e:
        print(f"Error in check_availability: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

    
@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # Pidetää token voimassa 1 tunti
    except (SignatureExpired, BadTimeSignature):
        flash('Vahvistuslinkki on virheellinen tai vanhentunut.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404() 

    if user.confirmed:
        flash('Sähköposti on jo vahvistettu.', 'info')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.utcnow()
        db.session.add(user)
        db.session.commit()
        flash('Sähköposti vahvistettu. Kiitos!', 'success')

    return redirect(url_for('login'))

@app.route('/my_profile')
@login_required
def my_profile():
    return render_template('my_profile.html')


@app.route('/upvote/<int:deal_id>', methods=['POST'])
@login_required
def upvote(deal_id):
    deal = Deal.query.get(deal_id)

    existing_vote = Vote.query.filter_by(user_id=current_user.id, deal_id=deal_id).first()

    if existing_vote:
        db.session.delete(existing_vote)
        deal.upvotes -= 1
    else:
        new_vote = Vote(user_id=current_user.id, deal_id=deal_id, vote_type='upvote')
        db.session.add(new_vote)
        deal.upvotes += 1

    db.session.commit()

    return jsonify({'success': True})


@app.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            # Obtén todos los deals de la base de datos
            deals = Deal.query.all()
            return render_template('admin_dashboard.html', deals=deals)
        else:
            return render_template('index.html')
    else:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        return redirect(url_for('login'))
    

@app.route('/validate_deal/<int:deal_id>', methods=['POST'])
def validate_deal(deal_id):
    # Aquí deberías realizar la lógica necesaria para cambiar el estado de `checked` a "Yes" en tu base de datos.
    # Esto es solo un ejemplo, y debes adaptarlo según tu modelo de datos.
    
    # Por ejemplo, si `Deal` tiene un atributo `checked` que es un enum ('Yes' o 'No'), podrías hacer algo como:
    deal = Deal.query.get(deal_id)
    deal.checked = 'Yes'
    db.session.commit()

    flash('Diili on hyväksytty', 'success')
    
    # Redirige de nuevo a la página del panel de administración
    return redirect(url_for('dashboard'))

@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']

        # Muodostaa paikallisen polun käyttäen os.path.join-ohjelmaa
        local_path = os.path.join(app.config['UPLOAD_FOLDER'], f"profile_pictures/user_{current_user.id}.jpg")
        
        # Tallenna kuva paikalliseen polkuun
        profile_picture.save(local_path)

        # Muuntaa reitin vinoviivoiksi verkkokäyttöä varten.
        web_path = local_path.replace(os.sep, '/')

        # Päivitä profiilikuvan polku tietokannassa
        current_user.profile_picture = web_path
        db.session.commit()

        flash('Kuva on lisätty oikein!', 'success')
    else:
        flash('Ei ole käyttäja kuvaa ladattu.', 'danger')

    return redirect(url_for('my_profile'))

@app.route('/downvote/<int:deal_id>', methods=['POST'])
@login_required
def downvote(deal_id):
    deal = Deal.query.get(deal_id)

    existing_vote = Vote.query.filter_by(user_id=current_user.id, deal_id=deal_id).first()

    if existing_vote:
        db.session.delete(existing_vote)
        deal.downvotes -= 1
    else:
        new_vote = Vote(user_id=current_user.id, deal_id=deal_id, vote_type='downvote')
        db.session.add(new_vote)
        deal.downvotes += 1

    db.session.commit()

    return jsonify({'success': True})



@app.route('/vote/<int:deal_id>/<vote_type>', methods=['POST'])
@login_required
def vote(deal_id, vote_type):
    deal = Deal.query.get(deal_id)

    #  tarkista, onko käyttäjä jo äänestänyt tätä diiliä
    existing_vote = Vote.query.filter_by(user_id=current_user.id, deal_id=deal_id).first()

    if existing_vote:
        # Jos käyttäjä on jo äänestänyt, tarkista, onko ääni sama kuin uusi ääni
        if existing_vote.vote_type == vote_type:
            flash('You have already voted this way.', 'warning')
        else:
            # Miinusta vanha ääni
            if existing_vote.vote_type == 'upvote':
                deal.upvotes -= 1
            elif existing_vote.vote_type == 'downvote':
                deal.downvotes -= 1

            # Vaihda ääni
            existing_vote.vote_type = vote_type

            # Päivitä uusi ääni
            if vote_type == 'upvote':
                deal.upvotes += 1
            elif vote_type == 'downvote':
                deal.downvotes += 1

            db.session.commit()
            
    else:
        # Jos käyttäjä ei ole vielä äänestänyt, luo uusi ääni
        new_vote = Vote(user_id=current_user.id, deal_id=deal_id, vote_type=vote_type)
        db.session.add(new_vote)

        # Päivitä uusi ääni
        if vote_type == 'upvote':
            deal.upvotes += 1
        elif vote_type == 'downvote':
            deal.downvotes += 1

        db.session.commit()
        

    # Palauta vastaus
    return redirect(url_for('view_deal', deal_id=deal.id))


@app.route('/check_deal', methods=['GET'])
def check_deal():
    offer_link = request.args.get('offer_link')

    # Tarkista, onko diili jo olemassa tietokannassa
    existing_deal = Deal.query.filter_by(offer_link=offer_link).first()

    if existing_deal:
        # Jos diili on jo olemassa, palauta diilin tiedot
        return jsonify({
            'exists': True,
            'title': existing_deal.title,
            'store': existing_deal.store,
            'description': existing_deal.description,
            'offer_price': existing_deal.offer_price,
            'regular_price': existing_deal.regular_price,
            'shipping_cost': existing_deal.shipping_cost,
            'category': existing_deal.category,
            'discount_code': existing_deal.discount_code,
            'expiration_date': existing_deal.expiration_date,
            'start_date': existing_deal.start_date,
            'photos': existing_deal.photos

            
        })
    else:
        # Jos diiliä ei ole vielä olemassa, palauta vastaus, jossa on tieto, että diiliä ei ole olemassa
        return jsonify({'exists': False})    
    

@app.route('/deal_details/<int:deal_id>')
def deal_details(deal_id):
    # Etsi diili tietokannasta käyttäen deal_id:tä
    deal = Deal.query.get(deal_id)

    if deal:
        
        return render_template('deal_details.html', deal=deal)
    else:
        # Jos diiliä ei löydy, ohjaa käyttäjä etusivulle ja näytä virheilmoitus
        flash('Diili ei löydy', 'error')
        return redirect(url_for('index'))
    

@app.route('/upload_deal', methods=['GET', 'POST'])
@login_required
def upload_deal_form():
    offer_link = session.pop('offer_link', None)

    if request.method == 'POST':
        # tarkista, onko diilin linkki jo olemassa tietokannassa
        existing_deal = Deal.query.filter_by(offer_link=offer_link).first()
        if existing_deal:
            flash('This offer has already been shared!', 'warning')
            return redirect(url_for('upload_deal'))

        # diilin julkaisupäivä
        publish_date = datetime.utcnow()
        start_date = request.form.get('start_date') or publish_date
        upvotes = request.form.get('upvotes', 0)
        downvotes = request.form.get('downvotes', 0)

        # Muu diilin tiedot
        new_deal = Deal(
            title=request.form.get('title'),
            store=request.form.get('store'),
            description=request.form.get('description'),
            publish_date=publish_date,
            expiration_date=request.form.get('expiration_date'),
            offer_link=request.form.get('offer_link'),
            user_id=current_user.id,
            offer_price=float(request.form.get('offer_price')),
            regular_price=float(request.form.get('regular_price')),
            discount_code=request.form.get('discount_code'),
            shipping_cost=float(request.form.get('shipping_cost')),
            start_date=start_date,
            category=request.form.get('category'),
            photos=json.dumps([]),  # alustaa tyhjän listan, johon lisätään kuvien polut myöhemmin
            upvotes=upvotes,
            downvotes=downvotes
        )

        db.session.add(new_deal)
        db.session.commit()

        deal_id = new_deal.id
        # Luo uusi kansio diilin kuvia varten
        deal_folder_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f"deals/deal_{deal_id}")
        os.makedirs(deal_folder_path, exist_ok=True)

        # Tallenna kuvat kansioon
        # Tallenna jokainen kuva kansioon ja lisää sen polku tietokantaan
        photo_paths = []
        for idx, photo in enumerate(request.files.getlist('photos')):
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                unique_name = f"{current_user.id}-{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}-{idx + 1}.{filename.rsplit('.', 1)[1].lower()}"
                photo_path = os.path.join(deal_folder_path, unique_name)
                photo.save(photo_path)
                photo_paths.append(photo_path)

                # Luo uusi rekordi tietokantaan
                new_image = Image(deal_id=new_deal.id, filename=unique_name)
                db.session.add(new_image)
        # Päivitys diilin kuvien poluista
        new_deal.photos = json.dumps(photo_paths)
        db.session.commit()

        flash('Deal uploaded successfully!', 'success')
        return redirect(url_for('index'))  

    return render_template('upload_deal_form.html',  offer_link=offer_link)

@app.route('/edit_deal/<int:deal_id>', methods=['GET', 'POST'])
@login_required
def edit_deal(deal_id):
    deal = Deal.get_deal_by_id(deal_id)
    
    # Verifica si el usuario actual es el propietario de la oferta
    if deal.user != current_user:
        flash('Sinulla ei ole lupaa muokata tätä tarjousta.', 'danger')
        return redirect(url_for('index'))

    form = DealForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            deal.title = form.title.data
            deal.description = form.description.data
            deal.offer_price = form.offer_price.data
            deal.regular_price = form.regular_price.data
            deal.store = form.store.data
            deal.expiration_date = form.expiration_date.data
            deal.discount_code = form.discount_code.data
            deal.shipping_cost = form.shipping_cost.data
            deal.start_date = form.start_date.data
            deal.category = form.category.data
            deal.photos = json.dumps([])  # Alustaa tyhjän listan, johon lisätään kuvien polut myöhemmin

            db.session.commit()
            flash('Diilin päivitys onnistui.', 'success')
            return redirect(url_for('my_profile'))

    elif request.method == 'GET':
        # Puedes prellenar el formulario con los valores actuales de la oferta
        form.title.data = deal.title
        form.description.data = deal.description
        form.offer_price.data = deal.offer_price
        form.regular_price.data = deal.regular_price
        form.store.data = deal.store
        form.expiration_date.data = deal.expiration_date
        form.start_date.data = deal.start_date
        form.discount_code.data = deal.discount_code
        form.shipping_cost.data = deal.shipping_cost        
        form.category.data = deal.category

    return render_template('edit_deal.html', title='Edit Deal', form=form, deal=deal)

@app.route('/end_deal/<int:deal_id>', methods=['POST'])
@login_required
def end_deal(deal_id):
    deal = Deal.query.get_or_404(deal_id)

    # Verificar si el usuario que intenta terminar el deal es el propietario del deal
    if current_user == deal.user:
        # Realizar las acciones necesarias para "terminar" el deal
        deal.end_deal()
        flash('Diili poisto onnistui', 'success')
    else:
        flash('Et voi poistaa diilia', 'error')

    return redirect(url_for('view_deal', deal_id=deal.id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)

            if form.remember_me.data:
                # Generar un token único y almacenarlo en una cookie
                token = str(uuid.uuid4())
                save_remember_token(user.id, token)

                response = make_response(redirect(url_for('index')))
                response.set_cookie('remember_token', token, max_age=30*24*60*60)  # La cookie expira en 30 días
                return response

            return redirect(url_for('index'))
        else:
            flash('Kirjautuminen epäonnistui. Tarkista käyttäjätunnuksesi ja salasanasi.', 'danger')

    return render_template('login.html', form=form)

def save_remember_token(user_id, token):
    remember_me_token = RememberMeToken(user_id=user_id, token=token)
    db.session.add(remember_me_token)
    db.session.commit()

    
@app.route('/logout')
def logout():
    print("Logging out user...")
    logout_user()
    flash('Uloskirjautuminen onnistui', 'success')
    return redirect(url_for('login'))


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm(request.form)

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data

        # Tarkista, onko nykyinen salasana oikein
        if not current_user.check_password(current_password):
            flash('Nykyinen salasana on virheellinen.', 'danger')
            return redirect(url_for('my_profile'))

        # Tarkista, onko uusi salasana sama kuin vahvistettu salasana
        if new_password != confirm_password:
            flash('Uudet salasanat eivät täsmää.', 'danger')
            return redirect(url_for('my_profile'))

        # Verificar la longitud mínima de la nueva contraseña
        if len(new_password) < 6:  # Ajusta la longitud mínima según tus necesidades
            flash('Uusi salasana on liian lyhyt.', 'danger')
            return redirect(url_for('my_profile'))

        try:
            # Generoidaan uusi salasanan hash
            new_password_hash = User.hash_password(new_password)

            # Päivitys tietokantaan
            current_user.password = new_password_hash
            db.session.commit()

            flash('Salasanan vaihto onnistui!', 'success')
            return redirect(url_for('my_profile'))
        except Exception as e:
            # Manejar excepciones de base de datos u otras excepciones
            flash('Virhe salasanan vaihdossa.', 'danger')
            return redirect(url_for('my_profile'))

    # Si el formulario no es válido, muestra mensajes de error en el formulario
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'{field.capitalize()}: {error}', 'danger')

    return redirect(url_for('my_profile'))


if __name__ == "__main__":
    with app.app_context():
        app.run(host='0.0.0.0', port=5000, debug=True)