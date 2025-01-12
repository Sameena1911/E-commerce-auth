from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, IntegerField,PasswordField, SubmitField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError, Optional, NumberRange
from datetime import date
import re
from flask_wtf.file import MultipleFileField, FileField, FileAllowed


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20, message="Username must be between 3 and 20 characters.")
    ])
    
    email = StringField('Email', validators=[DataRequired()])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match.")
    ])
    
    role = SelectField('Role', choices=[
        ('customer', 'Customer'),
        ('delivery', 'Delivery')
    ], validators=[DataRequired()])
    
    contact = StringField('Contact', validators=[
        DataRequired(),
        Regexp(r'^\d{10}$', message="Contact number must be 10 digits.")
    ])
    
    location = StringField('Location', validators=[DataRequired()])
    
    dob = DateField('Date of Birth', validators=[
        DataRequired(message="Please enter a valid date in the format YYYY-MM-DD.")
    ])
    
    gender = SelectField('Gender', choices=[
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    
    submit = SubmitField('Register')

    # Custom validator for the date of birth
    def validate_dob(self, dob):
        if dob.data > date.today():
            raise ValidationError("Date of Birth cannot be in the future.")

    # Custom email validation
    def validate_email(self, email):
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email.data):
            raise ValidationError("Enter a valid email address.")




class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0)], places=2)
    description = TextAreaField('Description', validators=[Optional()])
    category = StringField('Category', validators=[Optional()])
    size = StringField('Size', validators=[Optional()])
    colour = StringField('Colour', validators=[Optional()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=0)])
    manufacturer = StringField('Manufacturer', validators=[Optional()])
    country_of_origin = StringField('Country of Origin', validators=[Optional()])
    
    rating = DecimalField('Rating', validators=[Optional(), NumberRange(min=0, max=5)], places=1)
    discount = DecimalField('Discount', default=0.0, validators=[Optional()], places=2)
    images = MultipleFileField('Product Images', validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')
    ])
    submit = SubmitField('Add Product')























class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

