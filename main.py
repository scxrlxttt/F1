"""Connecting to flask retrieving Formula 1 data from an SQLite database."""

# ---------------
# Import SQL tools
# ---------------

import sqlite3
from sqlite3 import Error

from flask import Flask, redirect, render_template, request, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "formula1"
DATABASE = "F1.db"


# ---------------
# SQL Functions
# ---------------

def create_connection(db_file):
    """Create a connection to the database."""
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


def execute_query(query, params=()):
    """Execute query and return the results."""
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    if query.lower().startswith(('insert', 'update', 'delete')):
        con.commit()
    if query.lower().startswith("select"):
        list = cur.fetchall()
    else:
        list = None
    con.close()
    return list


def fetchone(query, params=()):
    """Execute query and return one."""
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    exists = cur.fetchone()
    con.close()
    return exists


# ---------------
# Teams
# ---------------

def get_teams():
    """Return the entire 'teams' table."""
    query = "SELECT * FROM teams ORDER BY constructor_position ASC"
    teams = execute_query(query, ())
    return teams


def get_team_info(team):
    """Return all info for a specific team."""
    query = "SELECT * FROM teams WHERE team_name=?"
    team_info = execute_query(query, (team, ))
    return team_info


def get_team_drivers(team):
    """Return the drivers on a specific team."""
    query = "SELECT * FROM drivers WHERE team_name=?"
    drivers = execute_query(query, (team, ))
    return drivers


# ---------------
# Drivers
# ---------------

def get_drivers():
    """Return the entire 'drivers' table."""
    query = "SELECT * FROM drivers ORDER BY championship_position ASC"
    drivers = execute_query(query, ())
    return drivers


def get_driver_info(driver):
    """Return a 'drivers' row for a specific driver."""
    query = "SELECT * FROM drivers WHERE driver_code = ?"
    driver_info = execute_query(query, (driver, ))
    return driver_info


# ---------------
# Races
# ---------------

def get_races():
    """Return a list of races."""
    query = "SELECT event_name FROM races"
    races = execute_query(query, ())
    if races:
        for i in range(len(races)):
            races[i] = races[i][0]
    return races


def get_race_info(race):
    """Return info for a specific race."""
    query = "SELECT * FROM races WHERE event_name=?"
    race_info = execute_query(query, (race, ))
    return race_info


# ---------------
# Race Results
# ---------------

def get_race_results(round):
    """Return race results for a specific race."""
    query = "SELECT * FROM results WHERE round=? ORDER BY position ASC"
    race_results = execute_query(query, (round, ))
    return race_results


# ---------------
# Sprint Results
# ---------------

def get_sprint_results(round):
    """Return sprint results for a specific sprint."""
    query = "SELECT * FROM sprint WHERE round=? ORDER BY position ASC"
    sprint_results = execute_query(query, (round, ))
    return sprint_results


# ---------------
# Users
# ---------------

def get_users():
    """Return the entire 'users' table."""
    query = "SELECT * FROM users ORDER BY id ASC"
    all_users = execute_query(query, ())
    return all_users


# ---------------
# Update Database
# ---------------

def update():
    """Update Driver and Team Points and Standings."""
    # Sum points from the 'results' table by driver
    query = "SELECT driver_code, COALESCE(SUM(points), 0) as total_race_points " \
            "FROM results GROUP BY driver_code"
    race_points = execute_query(query, ())
    race_points_dict = {row[0]: row[1] for row in race_points}

    # Sum points from the 'sprint' table by driver
    query = "SELECT driver_code, COALESCE(SUM(points), 0) as total_sprint_points " \
            "FROM sprint GROUP BY driver_code"
    sprint_points = execute_query(query, ())
    sprint_points_dict = {row[0]: row[1] for row in sprint_points}

    # Get all driver codes from the drivers table
    query = "SELECT driver_code FROM drivers"
    drivers = execute_query(query, ())

    # Update each driver's season_points (race + sprint points)
    if drivers:
        for driver in drivers:
            driver_code = driver[0]
            total_points = race_points_dict.get(driver_code, 0) \
                         + sprint_points_dict.get(driver_code, 0)

            query = "UPDATE drivers SET season_points = ? WHERE driver_code = ?"
            execute_query(query, (total_points, driver_code))

    # Order drivers based on their season points
    query = "SELECT driver_code, season_points FROM drivers ORDER BY season_points DESC"
    driver_rankings = execute_query(query, ())

    # Update the driver's position based on the order
    if driver_rankings:
        for position, (driver_code, _) in enumerate(driver_rankings, start=1):
            query = "UPDATE drivers SET championship_position = ? WHERE driver_code = ?"
            execute_query(query, (position, driver_code))

    # Update season wins and season podiums based on results table
    if drivers:
        for driver in drivers:
            driver_code = driver[0]

            # Count how many wins the driver has
            query = "SELECT COUNT(*) FROM results WHERE driver_code = ? " \
                    "AND position = 1"
            wins_result = execute_query(query, (driver_code,))
            wins = wins_result[0][0] if wins_result else 0

            # Count how many podiums the driver has
            query = "SELECT COUNT(*) FROM results WHERE driver_code = ? " \
                    "AND position <= 3"
            podiums_result = execute_query(query, (driver_code,))
            podiums = podiums_result[0][0] if podiums_result else 0

            # Fetch current career wins and podiums
            query = "SELECT pre_wins, pre_podiums FROM drivers WHERE driver_code = ?"
            career_stats = execute_query(query, (driver_code,))
            if career_stats:
                career_wins = career_stats[0][0]
                career_podiums = career_stats[0][1]
            else:
                career_wins = 0
                career_podiums = 0

            # Update season stats and new career totals
            career_wins += wins
            career_podiums += podiums

            query = """UPDATE drivers SET season_wins = ?, season_podiums = ?, " \
                    "career_wins = ?, career_podiums = ? WHERE driver_code = ?"""
            execute_query(query, (wins, podiums, career_wins, career_podiums, 
                                  driver_code))

            # Update the driver's season_wins and season_podiums
            query = "UPDATE drivers SET season_wins = ?, season_podiums = ? " \
                    "WHERE driver_code = ?"
            execute_query(query, (wins, podiums, driver_code))

    # Get all drivers and update team points
    query = "SELECT team_name, COALESCE(SUM(season_points), 0) as total_team_points " \
            "FROM drivers GROUP BY team_name"
    team_points = execute_query(query, ())

    # Update each team's season_points in the teams table
    if team_points:
        for team_name, total_points in team_points:
            if team_name == "Red Bull":
                total_points -= 3
            elif team_name == "Racing Bulls":
                total_points += 3

            query = "UPDATE teams SET season_points = ? WHERE team_name = ?"
            execute_query(query, (total_points, team_name))

    # Rank teams based on their season points
    query = "SELECT team_name, SUM(season_points) as total_team_points FROM drivers " \
            "GROUP BY team_name ORDER BY total_team_points DESC"
    team_rankings = execute_query(query, ())

    # Update the team's position based on the ranking
    if team_rankings:
        for position, (team_name, _) in enumerate(team_rankings, start=1):
            query = "UPDATE teams SET constructor_position = ? WHERE team_name = ?"
            execute_query(query, (position, team_name))


# ---------------
# Basic Webpages
# ---------------

@app.route('/')
def render_home():
    """Render the index page with a list of categories."""
    return render_template('index.html', teams=get_teams(), drivers=get_drivers())


@app.route('/teams')
def render_teams():
    """Render the team page with a list of teams."""
    return render_template('teams.html', teams=get_teams())


@app.route('/team/<team>')
def render_team(team):
    """Render the team page for a specific team."""
    return render_template('team.html', team_info=get_team_info(team),
                           drivers=get_team_drivers(team))


@app.route('/drivers')
def render_drivers():
    """Render the driver page with a list of drivers."""
    return render_template('drivers.html', drivers=get_drivers())


@app.route('/driver/<driver>')
def render_driver(driver):
    """Render the driver page for a specific team."""
    return render_template('driver.html', drivers=get_drivers(),
                           driver_info=get_driver_info(driver))


@app.route('/races')
def render_races():
    """Render the race page with a list of races."""
    return render_template('races.html', races=get_races())


@app.route('/race/<race>')
def render_race(race):
    """Render the race page for a specific race."""
    race_info = get_race_info(race)
    round = race_info[0][0]
    results = get_race_results(round)
    sprint = get_sprint_results(round)
    return render_template('race.html', races=get_races(), race_info=race_info,
                           results=results, sprint=sprint)

    
# ---------------
# Login, Logout, Signup
# ---------------

@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    # If already logged in, redirect to home
    if 'email' in session:
        return redirect('/')

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        query = "SELECT id, fname, password, admin FROM users WHERE email = ?"
        user_data = fetchone(query, (email,))

        # If email not found
        if user_data is None:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        try:
            user_id = user_data[0]
            first_name = user_data[1]
            db_password = user_data[2]
            is_admin = user_data[3]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # Check hashed password
        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        # Set session data
        session['email'] = email
        session['user_id'] = user_id
        session['firstname'] = first_name
        session['admin'] = is_admin

        return redirect('/')

    # GET request: render login page
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()  # More concise way to clear session
    return redirect('/?message=See+you+next+time!')


@app.route('/signup', methods = ['POST', 'GET'])
def render_signup_page():
  if request.method == 'POST':
    fname = request.form.get('fname').title().strip()
    lname = request.form.get('lname').title().strip()
    email = request.form.get('email').lower().strip()
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if password != password2:
      return redirect("/signup?error=Passwords+do+not+match")

    if len(password) < 8:
      return redirect("/signup?error=Password+must+be+at+least+8+characters")
    hashed_password = bcrypt.generate_password_hash(password)
    query = "INSERT INTO users(fname, lname, email, password, admin) " \
            "VALUES(?, ?, ?, ?, ?)"

    try:
      execute_query(query, (fname, lname, email, hashed_password, 0))
    except sqlite3.IntegrityError:
      return redirect('/signup?error=Email+is+already+used')

    return redirect("/login")
  return render_template('signup.html')


# ---------------
# Account
# ---------------

@app.route('/account')
def account():
    if 'email' not in session:
        return redirect('/login')

    id = session['user_id']

    # Get user details
    query = "SELECT * FROM users WHERE id = ?"
    user_details = execute_query(query, (id, ))

    # Get favourite teams
    query = "SELECT team FROM fav_teams WHERE user_id = ?"
    teams = execute_query(query, (id, ))

    # Get favourtie drivers
    query = "SELECT drivers.driver_code, drivers.driver_name FROM fav_drivers " \
            "JOIN drivers ON fav_drivers.driver = drivers.driver_code " \
            "WHERE fav_drivers.user_id = ?"
    drivers = execute_query(query, (id,))

    # Get favourite races
    query = "SELECT races.round, races.event_name FROM fav_races JOIN races " \
            "ON fav_races.race = races.round WHERE fav_races.user_id = ?"
    races = execute_query(query, (id,))

    return render_template('account.html', user_details=user_details, teams=teams,
                           drivers=drivers, races=races)


@app.route('/edit_account', methods=['POST'])
def edit_account():
    if 'email' not in session:  # require login
        return redirect('/login')

    id = session['user_id']
    
    fname = request.form['fname']
    lname = request.form['lname']
    email = request.form['email']

    query = "UPDATE users SET fname = ?, lname = ?, email = ? WHERE id = ?"
    execute_query(query, (fname, lname, email, id, ))

    return redirect('/account')


@app.route('/delete_account')
def delete_account():
    if 'email' not in session:  # require login
        return redirect('/login')
    id = session['user_id']
    query = "DELETE from users WHERE id = ?"
    execute_query(query, (id, ))
    return redirect('/logout')


@app.route('/delete_account/<id>')
def delete_accounts(id):
    if 'email' not in session:  # require login
        return redirect('/login')
    query = "DELETE from users WHERE id = ?"
    execute_query(query, (id, ))
    return redirect('/admin')


@app.route('/admin')
def admin():
    if 'email' not in session:
        return redirect('/login')

    if session['admin'] == 0:
        return redirect('/account')

    # Get all drivers
    query = "SELECT * FROM drivers"
    drivers = execute_query(query, ())

    # Get all teams
    query = "SELECT team_name FROM teams"
    teams = execute_query(query, ())

    # Get all races
    query = "SELECT round, event_name FROM races"
    races = execute_query(query, ())

    # Get all sprint races
    query = "SELECT round, event_name FROM races WHERE event_format = 'sprint'"
    sprints = execute_query(query, ())

    update()

    return render_template('admin.html', drivers=drivers, teams=teams, races=races,
                           sprints=sprints, users=get_users())


@app.route('/edit_admin/<id>', methods=['POST'])
def edit_admin(id):
    if 'email' not in session:  # require login
        return redirect('/login')

    if session['admin'] == 0:    # require admin
        return redirect('/account')

    admin = int(request.form['admin'])

    query = """UPDATE users SET admin = ? WHERE id = ?"""
    execute_query(query, (admin, id, ))

    return redirect('/admin')


# ---------------
# Favourites
# ---------------

@app.route('/add_fav_team/<team>')
def add_fav_team(team):
    if 'email' not in session:  # require login
        return redirect('/login')
    
    id = session['user_id']

    query = "SELECT 1 FROM fav_teams WHERE user_id = ? AND team = ?"
    exists = fetchone(query, (id, team, ))

    if not exists:
        query = "INSERT INTO fav_teams (user_id, team) VALUES (?, ?)"
        execute_query(query, (id, team))

    return redirect('/account')


@app.route('/add_fav_driver/<driver>')
def add_fav_driver(driver):
    if 'email' not in session:  # require login
        return redirect('/login')
    id = session['user_id']

    # Check for duplicates
    query = "SELECT 1 FROM fav_drivers WHERE user_id = ? AND driver = ?"
    exists = fetchone(query, (id, driver, ))

    if not exists:
        query = "INSERT INTO fav_drivers (user_id, driver) VALUES (?, ?)"
        execute_query(query, (id, driver))

    return redirect('/account')


@app.route('/add_fav_race/<race>')
def add_fav_race(race):
    if 'email' not in session:
        return redirect('/login')
    id = session['user_id']

    # Check for duplicates
    query = "SELECT 1 FROM fav_races WHERE user_id = ? AND race = ?"
    exists = fetchone(query, (id, race, ))
    if not exists:
        query = "INSERT INTO fav_races (user_id, race) VALUES (?, ?)"
        execute_query(query, (id, race, ))

    return redirect('/account')

    
@app.route('/remove_fav_team/<team>')
def remove_fav_team(team):
    if 'email' not in session:
        return redirect('/login')
    id = session['user_id']
    query = "DELETE from fav_teams WHERE user_id = ? AND team = ?"
    execute_query(query, (id, team, ))
    return redirect('/account')


@app.route('/remove_fav_driver/<driver>')
def remove_fav_driver(driver):
    if 'email' not in session:
        return redirect('/login')
    id = session['user_id']
    query = "DELETE from fav_drivers WHERE user_id = ? AND driver = ?"
    execute_query(query, (id, driver, ))
    return redirect('/account')


@app.route('/remove_fav_race/<race>')
def remove_fav_race(race):
    if 'email' not in session:
        return redirect('/login')
    id = session['user_id']
    query = "DELETE from fav_races WHERE user_id = ? AND race = ?"
    execute_query(query, (id, race, ))
    return redirect('/account')


# ---------------
# Edit Drivers
# ---------------

@app.route('/add_driver', methods=['POST'])
def add_driver():
    number = request.form['number']
    name = request.form['name'].title()
    code = request.form['code'].upper()
    team = request.form['team']
    country = request.form['country'].title()
    championships_won = request.form['championships_won']
    career_wins = request.form['career_wins']
    career_podiums = request.form['career_podiums']
    races_entered = request.form['races_entered']
    driver_description= request.form['driver_description']

    # Check if driver number or code already exists
    query = "SELECT 1 FROM drivers WHERE driver_number = ? OR driver_code = ? " \
                "OR driver_name = ?"
    exists = fetchone(query, (number, code, name))

    if exists:
        return redirect('/admin?error=Driver+already+exists')

    else:
        query = "INSERT INTO drivers (driver_number, driver_name, driver_code, " \
                "team_name, driver_country, championships_won, career_wins, " \
                "career_podiums, races_entered, driver_description) VALUES " \
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        execute_query(query, (number, name, code, team, country, championships_won, 
                              career_wins, career_podiums, races_entered, 
                              driver_description))
    
    return redirect('/admin')


@app.route('/edit_driver', methods=['POST'])
def edit_driver():
    driver_number = request.form['number']
    team = request.form['team']
    championships_won = request.form['championships_won']
    driver_description = request.form['driver_description']

    query = "UPDATE Drivers SET team_name = ?, championships_won = ?, " \
            "driver_description = ? WHERE driver_number = ?"
    execute_query(query, (team, championships_won, driver_description, driver_number, ))

    return redirect('/admin')


@app.route('/delete_driver', methods=['POST'])
def delete_driver():
    driver_number = request.form['driver_number']
    query = "DELETE FROM drivers WHERE driver_number = ?"
    execute_query(query, (driver_number,))
    return redirect('/admin')


# -------------------
# Edit Race Results
# -------------------

@app.route('/add_race_result', methods=['POST'])
def add_race_result():
    round = request.form['race']
    position = int(request.form['position'])
    driver_code = request.form['driver_code']

    points_for_positions = {1: 25, 2: 18, 3: 15, 4: 12, 5: 10, 6: 8, 7: 6, 8: 4, 9: 2, 10: 1}

    points = points_for_positions.get(position, 0)

    # Check if result already exists for this round and driver_code
    query = "SELECT 1 FROM results WHERE round = ? AND (driver_code = ? OR position = ?)"
    exists = fetchone(query, (round, driver_code, position))

    if exists:
        return redirect('/admin?error=Race+result+already+exists+for+this+driver+and+round')

    cur.execute("INSERT INTO results (round, position, driver_code, points) VALUES (?, ?, ?, ?)",
                (round, position, driver_code, points))
    con.commit()
    con.close()
    return redirect('/admin')


@app.route('/delete_race_result', methods=['POST'])
def delete_race_result():
    round = request.form['race']
    driver_code = request.form['driver_code']

    query = "DELETE FROM results WHERE round = ? AND driver_code = ?"
    execute_query(query, (round, driver_code))

    return redirect('/admin')


# -------------------
# Edit Sprint Results
# -------------------

@app.route('/add_sprint_result', methods=['POST'])
def add_sprint_result():
    round = request.form['race']
    position = int(request.form['position'])
    driver_code = request.form['driver_code']
    
    points_for_positions = {1: 8, 2: 7, 3: 6, 4: 5, 5: 4, 6: 3, 7: 2, 8: 1}

    points = points_for_positions.get(position, 0)

    # Check if result already exists for this round and driver_code
    query = "SELECT 1 FROM results WHERE round = ? AND (driver_code = ? OR position = ?)"
    exists = fetchone(query, (round, driver_code, position))

    if exists:
        return redirect('/admin?error=Sprint+result+already+exists+for+this+driver/position+and+round')

    else:
        query = "INSERT INTO sprint (round, position, driver_code, points) VALUES (?, ?, ?, ?)"
        execute_query(query, (round, position, driver_code, points))
    
    return redirect('/admin')


@app.route('/delete_sprint_result', methods=['POST'])
def delete_sprint_result():
    round = request.form['race']
    driver_code = request.form['driver_code']

    query = "DELETE FROM sprint WHERE round = ? AND driver_code = ?"
    execute_query(query, (round, driver_code))

    return redirect('/admin')


# ---------------
# Yippeee!!
# ---------------

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
