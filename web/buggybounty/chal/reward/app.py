from flask import Flask
import os

app = Flask(__name__)


@app.route('/bounty', methods=['GET'])
def get_bounty():
    flag = os.environ.get('FLAG')
    if flag:
        return flag


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)
