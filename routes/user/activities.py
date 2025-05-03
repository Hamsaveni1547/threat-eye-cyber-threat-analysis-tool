from flask import Blueprint, render_template, jsonify
from database import db
from flask_login import login_required, current_user
from datetime import datetime

activities_bp = Blueprint('activities', __name__)

@activities_bp.route('/activities')
@login_required
def activities():
    try:
        # Fetch activities for current user
        activities = db.execute("""
            SELECT 
                id,
                scanned_content,
                tool_used,
                created_at
            FROM user_activities 
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (current_user.id,))
        
        return render_template('user/activities.html', activities=activities)
        
    except Exception as e:
        return render_template('user/activities.html', 
                             error="Unable to fetch activities. Please try again later.")

@activities_bp.route('/api/activities')
@login_required
def get_activities():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        activities = db.execute("""
            SELECT 
                id,
                scanned_content,
                tool_used,
                created_at
            FROM user_activities 
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (current_user.id, per_page, (page-1)*per_page))
        
        return jsonify({
            'status': 'success',
            'data': activities
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch activities'
        }), 500
