import hashlib
from flask import render_template, make_response, redirect, url_for


def idor_login_page(request, app):
    return render_template('idor/idor_login.html')


def idor_login_api(request, app):
    form = request.form

    username = form.get('username')
    password = form.get('password')
    password = hashlib.md5(password.encode('utf-8')).hexdigest()

    db_result = app.db_helper.execute_read(
        f"SELECT * FROM users WHERE username=:username AND password=:password",
        { 'username': username, 'password': password }
    )

    if len(db_result) == 0:
        return render_template('idor/idor_login.html', error=True)

    user = list(
        map(
            lambda u: app.db_models.UserDbModel(u), 
            db_result
        )
    )[0]

    resp = make_response(redirect(url_for('idor_profile')))

    resp.set_cookie('user_id', str(user.id))
    resp.set_cookie('session_token', str(user.password))

    return resp


def idor_profile_page(request, app):
    session_token = request.cookies.get('session_token')

    if not session_token:
        return redirect(url_for('idor_login'))

    # Look up the user by their session_token (password hash) to authenticate
    # This prevents IDOR by only returning the profile of the authenticated user
    db_result = app.db_helper.execute_read(
        f"SELECT * FROM users WHERE password=:session_token",
        { 'session_token': session_token }
    )

    if len(db_result) == 0:
        return redirect(url_for('idor_login'))

    user = list(
        map(
            lambda u: app.db_models.UserDbModel(u),
            db_result
        )
    )[0]

    return render_template('idor/idor_profile.html', user=user)


