"""Connecting to flask retrieving Formula 1 data from an SQLite database."""

from flask import Flask, render_template, request
import sqlite3
from sqlite3 import Error

app = Flask(__name__)
DATABASE = "F1.db"


def create_connection(db_file):
    """Create a connection to the database."""
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None

def get_teams():
    """Return a list of teams"""
    con = create_connection(DATABASE)
    query = "SELECT team_name FROM teams"
    cur = con.cursor()
    cur.execute(query)
    teams = cur.fetchall()
    for i in range(len(teams)):
        teams[i] = teams[i][0]
    return teams
  
def get_drivers():
    """Return a list of drivers"""
    con = create_connection(DATABASE)
    query = "SELECT driver_code FROM drivers"
    cur = con.cursor()
    cur.execute(query)
    drivers = cur.fetchall()
    for i in range(len(drivers)):
        drivers[i] = drivers[i][0]
    return drivers

def get_races():
    """Return a list of races"""
    con = create_connection(DATABASE)
    query = "SELECT event_name FROM races"
    cur = con.cursor()
    cur.execute(query)
    races = cur.fetchall()
    for i in range(len(races)):
        races[i] = races[i][0]
    return races


@app.route('/')
def render_home():
    """Render the index page with a list of categories."""
    return render_template('index.html')

@app.route('/teams')
def render_teams():
    """Render the team page with a list of teams."""
    return render_template('teams.html', teams=get_teams())

@app.route('/team/<team>')
def render_circuits(team):
    """Render the team page for a specific team."""
    print(team)
    return render_template('team.html', teams=get_teams())

@app.route('/drivers')
def render_drivers():
    """Render the driver page with a list of drivers."""
    return render_template('drivers.html', drivers=get_drivers())

@app.route('/driver')
def render_driver():
    """Render the driver page for a specific team."""
    return render_template('driver.html', drivers=get_drivers())

@app.route('/races')
def render_races():
    """Render the race page with a list of races."""
    return render_template('races.html', races=get_races())

@app.route('/race')
def render_race():
    """Render the race page for a specific race."""
    return render_template('race.html', races=get_races())


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=81)
