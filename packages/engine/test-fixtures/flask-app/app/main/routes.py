import yaml
from flask import request, render_template_string
from flask_login import login_required

from app.main import bp


@bp.route('/')
def index():
    return 'hello'


@bp.route('/preview', methods=['POST'])
def preview():
    tpl = request.form['t']
    return render_template_string(tpl)


@bp.route('/config', methods=['POST'])
@login_required
def config():
    data = yaml.load(request.data)
    return str(data)


def helper(text):
    return yaml.load(text)
