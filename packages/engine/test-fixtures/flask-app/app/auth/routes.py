from flask import request

from app.auth import bp


@bp.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form.get('username')
    return 'login ' + str(username)
