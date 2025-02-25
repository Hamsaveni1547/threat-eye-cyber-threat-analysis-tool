from flask import Flask, render_template

todo = Flask(__name__)


@todo.route('/')
def home():
    return render_template('home.html')


@todo.route('/about')
def about():
    return render_template('about.html')


@todo.route('/contact')
def contact():
    return render_template('contact.html')


if __name__ == '__main__':
    todo.run(
        host='127.0.0.1',
        port=5006,
        debug=True
    )