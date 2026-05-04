from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "GoodGate Network System is Active"

if __name__ == '__main__':
    app.run(debug=True)
