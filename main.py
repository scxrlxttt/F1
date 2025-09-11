"""Connecting to flask retrieving Formula 1 data from an SQLite database."""

# ---------------
# Import SQL tools
# ---------------

from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "formula1"
DATABASE = "F1.db"


# ---------------
# Functions
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
    """Helper function to execute a query and return the results."""
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    if query.lower().startswith(('insert', 'update', 'delete')):
        con.commit()  # Commit if the query modifies data (INSERT/UPDATE/DELETE)

    if query.lower().startswith("select"):
        list = cur.fetchall()  # Fetch results for SELECT queries
    else:
        list = None  # For non-SELECT queries (INSERT, UPDATE, DELETE)
    con.close()
    return list


# TEAMS
def get_teams():
    """Return a list of teams"""
    query = "SELECT team_name FROM teams"
    teams = execute_query(query, ())
    for i in range(len(teams)):
        teams[i] = teams[i][0]
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


def all_team_info():
    """Return the entire 'teams' table."""
    query = "SELECT * FROM teams ORDER BY constructor_position ASC"
    all_info = execute_query(query, ())
    return all_info


# DRIVERS
def get_drivers():
    """Return a list of drivers"""
    query = "SELECT driver_name FROM drivers ORDER BY driver_name ASC"
    drivers = execute_query(query, ())
    for i in range(len(drivers)):
        drivers[i] = drivers[i][0]
    return drivers


def get_driver_info(driver):
    """Return a 'drivers' row for a specific driver"""
    query = "SELECT * FROM drivers WHERE driver_name=?"
    driver_info = execute_query(query, (driver, ))
    return driver_info


def all_driver_info():
    """Return the entire 'drivers' table."""
    query = "SELECT * FROM drivers ORDER BY championship_position ASC"
    all_info = execute_query(query, ())
    return all_info


# RACES
def get_races():
    """Return a list of races."""
    query = "SELECT event_name FROM races"
    races = execute_query(query, ())
    for i in range(len(races)):
        races[i] = races[i][0]
    return races


def get_race_info(race):
    """Return info for a specific race."""
    query = "SELECT * FROM races WHERE event_name=?"
    race_info = execute_query(query, (race, ))
    return race_info


# RACE RESULTS
def get_race_results(round):
    """Return race results for a specific race."""
    query = "SELECT * FROM results WHERE round=? ORDER BY position ASC"
    race_results = execute_query(query, (round, ))
    return race_results


# SPRINT RESULTS
def get_sprint_results(round):
    """Return sprint results for a specific sprint."""
    query = "SELECT * FROM sprint WHERE round=? ORDER BY position ASC"
    sprint_results = execute_query(query, (round, ))
    return sprint_results


#LOGIN
def is_logged_in():
  if session.get("email") is None:
    print("not logged in")
    return False
  else:
    print("logged in")
    return True


# UPDATE DATABASE
def update():
    """Update Driver and Team Points and Standings."""

    # Sum points from the 'results' table by driver
    query = "SELECT driver_code, COALESCE(SUM(points), 0) as total_race_points FROM results GROUP BY driver_code"
    race_points = execute_query(query, ())
    race_points_dict = {row[0]: row[1] for row in race_points}

    # Sum points from the 'sprint' table by driver
    query = "SELECT driver_code, COALESCE(SUM(points), 0) as total_sprint_points FROM sprint GROUP BY driver_code"
    sprint_points = execute_query(query, ())
    sprint_points_dict = {row[0]: row[1] for row in sprint_points}

    # Get all driver codes from the drivers table
    query = "SELECT driver_code FROM drivers"
    drivers = execute_query(query, ())

    # Update each driver's season_points (sum of race + sprint points)
    if drivers:
        for driver in drivers:
            driver_code = driver[0]
            total_points = race_points_dict.get(driver_code, 0) + sprint_points_dict.get(driver_code, 0)

            query = "UPDATE drivers SET season_points = ? WHERE driver_code = ?"
            execute_query(query, (total_points, driver_code))


    # Rank drivers based on their season points
    query = "SELECT driver_code, season_points FROM drivers ORDER BY season_points DESC"
    driver_rankings = execute_query(query, ())

    # Update the driver's position based on the ranking
    if driver_rankings:
        for position, (driver_code, _) in enumerate(driver_rankings, start=1):
            query = "UPDATE drivers SET championship_position = ? WHERE driver_code = ?"
            execute_query(query, (position, driver_code))

    # Update season wins and season podiums based on results table
    if drivers:
        for driver in drivers:
            driver_code = driver[0]

            # Count how many wins (position = 1) this driver has in the 'results' table
            query = "SELECT COUNT(*) FROM results WHERE driver_code = ? AND position = 1"
            wins_result = execute_query(query, (driver_code,))
            wins = wins_result[0][0] if wins_result else 0

            # Count how many podiums (positions <= 3) this driver has in the 'results' table
            query = "SELECT COUNT(*) FROM results WHERE driver_code = ? AND position <= 3"
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

            query = """UPDATE drivers SET season_wins = ?, season_podiums = ?, career_wins = ?, career_podiums = ? WHERE driver_code = ?"""
            execute_query(query, (wins, podiums, career_wins, career_podiums, driver_code))

            # Update the driver's season_wins and season_podiums
            query = "UPDATE drivers SET season_wins = ?, season_podiums = ? WHERE driver_code = ?"
            execute_query(query, (wins, podiums, driver_code))

    # Get all drivers and update team points
    query = "SELECT team_name, COALESCE(SUM(season_points), 0) as total_team_points FROM drivers GROUP BY team_name"
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
    query = "SELECT team_name, SUM(season_points) as total_team_points FROM drivers GROUP BY team_name ORDER BY total_team_points DESC"
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
    return render_template('index.html', all_team_info=all_team_info(), all_driver_info=all_driver_info()) 


@app.route('/teams')
def render_teams():
    """Render the team page with a list of teams."""
    return render_template('teams.html', teams=get_teams(), all_team_info=all_team_info())


@app.route('/team/<team>')
def render_team(team):
    """Render the team page for a specific team."""
    return render_template('team.html', teams=get_teams(), team_info=get_team_info(team), drivers=get_team_drivers(team), title=team)


@app.route('/drivers')
def render_drivers():
    """Render the driver page with a list of drivers."""
    return render_template('drivers.html', drivers=get_drivers(), all_driver_info=all_driver_info())


@app.route('/driver/<driver>')
def render_driver(driver):
    """Render the driver page for a specific team."""
    return render_template('driver.html', drivers=get_drivers(), driver_info=get_driver_info(driver), title=driver)


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
    print(sprint)
    return render_template('race.html', races=get_races(), race_info=race_info, results=results, sprint=sprint, title=race)


# ---------------
# Login, Logout, Signup
# ---------------

@app.route('/login', methods = ['POST', 'GET'])
def render_login_page():
  if is_logged_in():
    return redirect('/')
  if request.method == 'POST':
    email = request.form['email'].strip().lower()
    password = request.form['password'].strip()
    
    query = "SELECT id, fname, password, admin FROM user WHERE email =?"

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, (email,))
    user_data = cur.fetchone() # only one value
    con.close()
    
      #if the given email is not in the database it will raise an error
    if user_data is None:
      return redirect("/login?error=Email+invalid+or+password+incorrect")

    try:
        user_id = user_data[0]
        first_name = user_data[1]
        db_password = user_data[2]
        is_admin = user_data[3]
    except IndexError:
      return redirect("/login?error=Email+invalid+or+password+incorrect")

    if not bcrypt.check_password_hash(db_password, password):
      return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

    session['email'] = email
    session['user_id'] = user_id
    session['firstname'] = first_name
    session['admin'] = is_admin

    print(session)
    return redirect('/')

  return render_template('login.html',logged_in = is_logged_in())


@app.route('/logout')
def logout():
    # Print current session keys before logout
    print("Before logout:", list(session.keys()))

    # Clear all session variables
    for key in list(session.keys()):
        session.pop(key)

    # Print session keys after logout (should be empty)
    print("After logout:", list(session.keys()))

    # Redirect to home with a message
    return redirect('/?message=See+you+next+time!')


@app.route('/signup', methods = ['POST', 'GET'])
def render_signup_page():
  if request.method == 'POST':
    print(request.form)
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
    print(hashed_password)  
    con = create_connection(DATABASE)
    query = "INSERT INTO user(fname, lname, email, password, admin) VALUES(?, ?, ?, ?, ?)"
    cur = con.cursor()

    try:
      cur.execute(query, (fname, lname, email, hashed_password, 0))
    except sqlite3.IntegrityError:
      con.close()
      return redirect('/signup?error=Email+is+already+used')

    con.commit()  
    con.close()

    return redirect("/login")
  return render_template('signup.html')


# ---------------
# Admin
# ---------------

@app.route('/admin')
def admin():
    if 'email' not in session:  # require login
        return redirect('/login')

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
    return render_template('admin.html', drivers=drivers, teams=teams, races=races, sprints=sprints)



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

    con = create_connection(DATABASE)
    cur = con.cursor()

    # Check if driver number or code already exists
    cur.execute("SELECT 1 FROM drivers WHERE driver_number = ? OR driver_code = ? OR driver_name = ?", (number, code, name))
    exists = cur.fetchone()

    if exists:
        con.close()
        # You can flash a message or redirect with an error query param
        return redirect('/admin?error=Driver+already+exists')
        
    cur.execute("INSERT INTO Drivers (driver_number, driver_name, driver_code, team_name, driver_country, championships_won, career_wins, career_podiums, races_entered, driver_description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                (number, name, code, team, country, championships_won, career_wins, career_podiums, races_entered, driver_description))
    
    con.commit()
    con.close()

    update_points()
    
    return redirect('/admin')


@app.route('/edit_driver', methods=['POST'])
def edit_driver():
    driver_number = request.form['number']
    team = request.form['team']
    championships_won = request.form['championships_won']
    driver_description = request.form['driver_description']

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute("""
        UPDATE Drivers SET team_name = ?, championships_won = ?, driver_description = ? WHERE driver_number = ?""", (team, championships_won, driver_description, driver_number))

    con.commit()
    con.close()

    update_points()

    return redirect('/admin')


@app.route('/delete_driver', methods=['POST'])
def delete_driver():
    driver_number = request.form['driver_number']
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute("DELETE FROM drivers WHERE driver_number = ?", (driver_number,))
    con.commit()
    con.close()
    update_points()
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

    con = create_connection(DATABASE)
    cur = con.cursor()

    # Check if result already exists for this round and driver_code
    cur.execute("SELECT 1 FROM results WHERE round = ? AND (driver_code = ? OR position = ?)", (round, driver_code, position))
    exists = cur.fetchone()

    if exists:
        con.close()
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

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute("DELETE FROM results WHERE round = ? AND driver_code = ?", 
                (round, driver_code))
    con.commit()
    con.close()
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

    con = create_connection(DATABASE)
    cur = con.cursor()

    # Check if result already exists for this round and driver_code
    cur.execute("SELECT 1 FROM results WHERE round = ? AND (driver_code = ? OR position = ?)", (round, driver_code, position))
    exists = cur.fetchone()

    if exists:
        con.close()
        return redirect('/admin?error=Race+result+already+exists+for+this+driver/position+and+round')

    cur.execute("INSERT INTO sprint (round, position, driver_code, points) VALUES (?, ?, ?, ?)", (round, position, driver_code, points))
    con.commit()
    con.close()
    return redirect('/admin')


@app.route('/delete_sprint_result', methods=['POST'])
def delete_sprint_result():
    round = request.form['race']
    driver_code = request.form['driver_code']

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute("DELETE FROM sprint WHERE round = ? AND driver_code = ?", 
                (round, driver_code))
    con.commit()
    con.close()
    return redirect('/admin')


# ---------------
# Yippeee!!
# ---------------

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
