from flask import Flask, render_template, jsonify
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from sqlalchemy import func
import io
import base64
from . import db
from . models import *
from flask import Blueprint
visualization = Blueprint('visualization',__name__,static_folder='static')


@visualization.route('/')
def home():
    # Render the home page without any chart data
    return render_template('roles.html', chart_url=None)
@visualization.route('/roles-chart')
def roles_chart():
    # Generate chart only when this route is accessed
    roles_data = db.session.query(User.role, db.func.count(User.role)).group_by(User.role).all()
    if not roles_data:
        return "No data available to generate chart."

    roles, counts = zip(*roles_data)
    fig = Figure()
    ax = fig.subplots()
    ax.bar(roles, counts, color='skyblue')
    ax.set_title('Users by Role')
    ax.set_xlabel('Role')
    ax.set_ylabel('Count')
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    img = io.BytesIO()
    fig.savefig(img, format='png')
    img.seek(0)

    chart_url = base64.b64encode(img.getvalue()).decode()
    return render_template('roles.html', chart_url=chart_url,title="users by role")


@visualization.route('/sales-by-city')
def sales_by_city():
    # Query database to group users by city and calculate sales (mock data below)
    city_sales = db.session.query(User.location, db.func.count(User.id)).group_by(User.location).all()

    # Data preparation for visualization
    cities = [item[0] for item in city_sales]
    sales = [item[1] * 100 for item in city_sales]  # Assuming each user contributes $100 to sales

    # Create bar chart with three basic colors
    fig = Figure()
    ax = fig.subplots()
    colors = ['#FF9999', '#99CCFF', '#FFCC99']  # Three basic colors (light red, blue, and orange)
    ax.bar(cities, sales, color=colors[:len(cities)])
    ax.set_title('Sales by City', fontsize=16)
    ax.set_xlabel('City', fontsize=12)
    ax.set_ylabel('Sales ($)', fontsize=12)
    ax.set_xticklabels(cities, rotation=45, ha='right')

    # Save chart to BytesIO object
    img = io.BytesIO()
    fig.savefig(img, format='png')
    img.seek(0)
    chart_url = base64.b64encode(img.getvalue()).decode()

    # Pass chart URL and data to the template
    return render_template('roles.html', chart_url=chart_url, city_sales=city_sales,title='sales by city',side_title='Real Time data',t1='City',t2='Sales')

@visualization.route('/order-insights')
def order_insights():
    # Fetch data from the Order table
    total_orders = db.session.query(func.count(Order.id)).scalar()
    total_revenue = db.session.query(func.sum(Order.order_amount)).scalar()
    
    # Fake growth logic for demonstration
    cagr = 22.4  # Assuming a constant CAGR
    revenue_2023 = total_revenue or 10.2  # Default starting point in billion dollars
    revenue_2032 = revenue_2023 * ((1 + (cagr / 100)) ** 9)  # Compound growth
    
    # Generate yearly growth chart (2024-2032)
    years = list(range(2024, 2033))
    revenues = [revenue_2023 * ((1 + (cagr / 100)) ** i) for i in range(len(years))]
    
    # Create a bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(years, revenues, color="#f7c74f")  # Yellow bars (subtle color)
    plt.title("Projected Revenue Growth", fontsize=16, weight='bold')
    plt.ylabel("Revenue (Billion USD)", fontsize=12)
    plt.xlabel("Year", fontsize=12)
    plt.xticks(years, rotation=45)
    plt.tight_layout()

    # Convert chart to base64
    chart_img = io.BytesIO()
    plt.savefig(chart_img, format='png', bbox_inches="tight")
    chart_img.seek(0)
    chart_url = base64.b64encode(chart_img.getvalue()).decode('utf8')
    plt.close()

    # Real-time analytics
    recent_orders = db.session.query(Order.order_date, Order.order_amount).order_by(Order.order_date.desc()).limit(5).all()
    report_data = [{"date": order.order_date, "amount": order.order_amount} for order in recent_orders]

    # Render HTML template with chart and data
    return render_template('roles.html', 
                           chart_url=chart_url, 
                           total_orders=total_orders, 
                           total_revenue=total_revenue, 
                           cagr=cagr, 
                           revenue_2032=round(revenue_2032, 2),
                           report_data=report_data,title='Order Insights',side_title='Real time data',total_order_title='Total Orders:',total_revenue_title='Total Revenue:',percentage='%',cagr_title='CAGR:',dollar='$',money='Billion',revenue_2032_title='Projected Revenue in 2032:',report_title='Recent Orders:')