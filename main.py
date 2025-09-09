"""Connecting to flask retrieving Formula 1 data from an SQLite database."""

from flask import Flask, render_template, redirect, request
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from flask import session

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "formula1"
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


def get_team_info(team):
    """"""
    title = team
    query = "SELECT * FROM teams WHERE team_name=?"
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Query the DATABASE
    cur.execute(query, (title, ))
    team_info = cur.fetchall()
    con.close()
    return team_info

def get_team_drivers(team):
    """"""
    title = team
    query = "SELECT * FROM drivers WHERE team_name=?"
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Query the DATABASE
    cur.execute(query, (title, ))
    drivers = cur.fetchall()
    con.close()
    return drivers

def all_team_info():
    """Return the entire 'teams' table."""
    con = create_connection(DATABASE)
    query = "SELECT * FROM teams ORDER BY constructor_position ASC"
    cur = con.cursor()
    cur.execute(query)
    all_info = cur.fetchall()
    return all_info


def get_drivers():
    """Return a list of drivers"""
    con = create_connection(DATABASE)
    query = "SELECT driver_name FROM drivers ORDER BY driver_name ASC"
    cur = con.cursor()
    cur.execute(query)
    drivers = cur.fetchall()
    for i in range(len(drivers)):
        drivers[i] = drivers[i][0]
    return drivers


def get_driver_info(driver):
    """Return a 'drivers' row for a specific driver"""
    title = driver
    query = "SELECT * FROM drivers WHERE driver_name=?"
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Query the DATABASE
    cur.execute(query, (title, ))
    driver_info = cur.fetchall()
    con.close()
    return driver_info

def all_driver_info():
    """Return the entire 'drivers' table."""
    con = create_connection(DATABASE)
    query = "SELECT * FROM drivers ORDER BY championship_position ASC"
    cur = con.cursor()
    cur.execute(query)
    all_info = cur.fetchall()
    return all_info


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


def get_race_info(race):
    """Return the entire 'races' table."""
    title = race
    query = "SELECT * FROM races WHERE event_name=?"
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Query the DATABASE
    cur.execute(query, (title, ))
    race_info = cur.fetchall()
    con.close()
    return race_info

def get_race_results(round):
    """"""
    query = "SELECT * FROM results WHERE round=? ORDER BY position ASC"
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Query the DATABASE
    cur.execute(query, (round, ))
    race_results = cur.fetchall()
    con.close()
    return race_results

def get_sprint_results(round):
    """"""
    query = "SELECT * FROM sprint WHERE round=? ORDER BY position ASC"
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Query the DATABASE
    cur.execute(query, (round, ))
    sprint_results = cur.fetchall()
    con.close()
    return sprint_results


def update_points():
    con = create_connection(DATABASE)
    cursor = con.cursor()

    # Sum points from the 'results' table grouped by driver_id
    cursor.execute("""
        SELECT driver_code, COALESCE(SUM(points), 0) as total_race_points
        FROM results
        GROUP BY driver_code
    """)
    race_points = cursor.fetchall()
    race_points_dict = {row[0]: row[1] for row in race_points}

    # Sum points from the 'sprint' table grouped by driver_id
    cursor.execute("""
        SELECT driver_code, COALESCE(SUM(points), 0) as total_sprint_points
        FROM sprint
        GROUP BY driver_code
    """)
    sprint_points = cursor.fetchall()
    sprint_points_dict = {row[0]: row[1] for row in sprint_points}

    # Get all driver codes from the drivers table
    cursor.execute("SELECT driver_code FROM drivers")
    drivers = cursor.fetchall()

    # Update each driver's season_points = sum of race + sprint points
    for driver in drivers:
        driver_id = driver[0]
        total_points = race_points_dict.get(driver_id, 0) + sprint_points_dict.get(driver_id, 0)

        cursor.execute("""
            UPDATE drivers
            SET season_points = ?
            WHERE driver_code = ?
        """, (total_points, driver_id))

    con.commit()

    # Rank drivers based on their season points
    cursor.execute("""
        SELECT driver_code, season_points
        FROM drivers
        ORDER BY season_points DESC
    """)
    driver_rankings = cursor.fetchall()

    # Update the driver's position based on the ranking
    for position, (driver_number, _) in enumerate(driver_rankings, start=1):
        cursor.execute("""
            UPDATE drivers
            SET championship_position = ?
            WHERE driver_code = ?
        """, (position, driver_number))

    # Update season wins and season podiums based on results table
    for driver in drivers:
        driver_code = driver[0]

        # Count how many wins (position = 1) this driver has in the 'results' table
        cursor.execute("""
            SELECT COUNT(*) FROM results
            WHERE driver_code = ? AND position = 1
        """, (driver_code,))
        wins = cursor.fetchone()[0]

        # Count how many podiums (positions <= 3) this driver has in the 'results' table
        cursor.execute("""
            SELECT COUNT(*) FROM results
            WHERE driver_code = ? AND position <= 3
        """, (driver_code,))
        podiums = cursor.fetchone()[0]

        # Update the driver's season_wins and season_podiums
        cursor.execute("""
            UPDATE drivers
            SET season_wins = ?, season_podiums = ?
            WHERE driver_code = ?
        """, (wins, podiums, driver_code))

    con.commit()

    # Get all drivers and update team points
    cursor.execute("""
        SELECT team_name, COALESCE(SUM(season_points), 0) as total_team_points
        FROM drivers
        GROUP BY team_name
    """)
    team_points = cursor.fetchall()

    # Update each team's season_points in the teams table
    for team_name, total_points in team_points:
        if team_name == "Red Bull":
            total_points -= 3
        elif team_name == "Racing Bulls":
            total_points += 3
        
        cursor.execute("""
            UPDATE teams
            SET season_points = ?
            WHERE team_name = ?
        """, (total_points, team_name))

    con.commit()

    # Rank teams based on their season points
    cursor.execute("""
        SELECT team_name, SUM(season_points) as total_team_points
        FROM drivers
        GROUP BY team_name
        ORDER BY total_team_points DESC
    """)
    team_rankings = cursor.fetchall()

    # Update the team's position based on the ranking
    for position, (team_name, _) in enumerate(team_rankings, start=1):
        cursor.execute("""
            UPDATE teams
            SET constructor_position = ?
            WHERE team_name = ?
        """, (position, team_name))

    con.commit()
    con.close()



@app.route('/')
def render_home():
    """Render the index page with a list of categories."""
    return render_template('index.html', all_team_info=all_team_info(), all_driver_info=all_driver_info()) 


@app.route('/teams')
def render_teams():
    """Render the team page with a list of teams."""
    update_points()
    return render_template('teams.html', teams=get_teams(), all_team_info=all_team_info())

@app.route('/team/<team>')
def render_team(team):
    """Render the team page for a specific team."""
    update_points()
    return render_template('team.html', teams=get_teams(), team_info=get_team_info(team), drivers=get_team_drivers(team), title=team)


@app.route('/drivers')
def render_drivers():
    """Render the driver page with a list of drivers."""
    update_points()
    return render_template('drivers.html', drivers=get_drivers(), all_driver_info=all_driver_info())

@app.route('/driver/<driver>')
def render_driver(driver):
    """Render the driver page for a specific team."""
    update_points()
    return render_template('driver.html', drivers=get_drivers(), driver_info=get_driver_info(driver), title=driver)


@app.route('/races')
def render_races():
    """Render the race page with a list of races."""
    return render_template('races.html', races=get_races())

@app.route('/race/<race>')
def render_race(race):
    """Render the race page for a specific race."""
    update_points()
    race_info = get_race_info(race)
    round = race_info[0][0]
    results = get_race_results(round)
    sprint = get_sprint_results(round)
    print(sprint)
    return render_template('race.html', races=get_races(), race_info=race_info, results=results, sprint=sprint, title=race)


@app.route('/login', methods = ['POST', 'GET'])
def render_login_page():
  if is_logged_in():
    return redirect('/')
  print("Logging in")
  if request.method == 'POST':
    print(request.form)
    email = request.form['email'].strip().lower()
    password = request.form['password'].strip()
    print(email)
    query = "SELECT id, fname, password FROM user WHERE email =?"

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, (email,))
    user_data = cur.fetchone() #only one value
    con.close()
    #if the given email is not in the database it will raise an error
    if user_data is None:
      return redirect("/login?error=Email+invalid+or+password+incorrect")

    try:
      user_id = user_data[0]
      first_name = user_data[1]
      db_password = user_data[2]
    except IndexError:
      return redirect("/login?error=Email+invalid+or+password+incorrect")

    if not bcrypt.check_password_hash(db_password, password):
      return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

    session['email'] = email
    session['user_id'] = user_id
    session['firstname'] = first_name

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
    query = "INSERT INTO user(fname, lname, email, password) VALUES(?, ?, ?, ?)"
    cur = con.cursor()

    try:
      cur.execute(query, (fname, lname, email, hashed_password)) #this line actually executes the query
    except sqlite3.IntegrityError:
      con.close()
      return redirect('/signup?error=Email+is+already+used')

    con.commit()  
    con.close()

    return redirect("/login")
  return render_template('signup.html')

def is_logged_in():
  if session.get("email") is None:
    print("not logged in")
    return False
  else:
    print("logged in")
    return True


@app.route('/admin')
def admin():
    if 'email' not in session:  # require login
        return redirect('/login')
    con = create_connection(DATABASE)
    cur = con.cursor()

    # Get all drivers
    cur.execute("SELECT * FROM drivers")
    drivers = cur.fetchall()

    # Get all teams
    cur.execute("SELECT team_name FROM teams")
    teams = cur.fetchall()

    # Get all races
    cur.execute("SELECT round, event_name FROM races")
    races = cur.fetchall()

    # Get all sprint races
    cur.execute("SELECT round, event_name FROM races WHERE event_format = 'sprint'")
    sprints = cur.fetchall()

    con.close()
    update_points()
    return render_template('admin.html', drivers=drivers, teams=teams, races=races, sprints=sprints)


# -------------------
# DRIVERS
# -------------------
@app.route('/add_driver', methods=['POST'])
def add_driver():
    number = request.form['number']
    name = request.form['name']
    code = request.form['code']
    team = request.form['team']
    country = request.form['country']
    championships_won = request.form['championships_won']
    career_wins = request.form['career_wins']
    career_podiums = request.form['career_podiums']
    races_entered = request.form['races_entered']
    driver_description= request.form['driver_description']

    con = create_connection(DATABASE)
    cur = con.cursor()

    # Check if driver number or code already exists
    cur.execute("SELECT 1 FROM drivers WHERE driver_number = ? OR driver_code = ?", (number, code))
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
    country = request.form['country']
    championships_won = request.form['championships_won']
    career_wins = request.form['career_wins']
    career_podiums = request.form['career_podiums']
    races_entered = request.form['races_entered']
    driver_description = request.form['driver_description']

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute("""
        UPDATE Drivers SET team_name = ?, driver_country = ?, championships_won = ?, career_wins = ?, career_podiums = ?, races_entered = ?, driver_description = ? WHERE driver_number = ?""", (team, country,championships_won, career_wins, career_podiums, races_entered, driver_description, driver_number))

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
# RACE RESULTS
# -------------------
@app.route('/add_race_result', methods=['POST'])
def add_race_result():
    round = request.form['race']
    position = int(request.form['position'])
    driver_code = request.form['driver_code']

    points_for_positions = {
        1: 25,
        2: 18,
        3: 15,
        4: 12,
        5: 10,
        6: 8,
        7: 6,
        8: 4,
        9: 2,
        10: 1
    }

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
# SPRINT RESULTS
# -------------------
@app.route('/add_sprint_result', methods=['POST'])
def add_sprint_result():
    round = request.form['race']
    position = int(request.form['position'])
    driver_code = request.form['driver_code']
    
    points_for_positions = {
        1: 8,
        2: 7,
        3: 6,
        4: 5,
        5: 4,
        6: 3,
        7: 2,
        8: 1,
    }

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


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
