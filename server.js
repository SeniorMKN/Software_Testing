const express = require('express');
const bodyParser = require('body-parser'); // Middleware to parse request bodies
const sqlite3 = require('sqlite3').verbose(); // SQLite module
const app = express();
const port = 3000; // You can change this port number if needed
const fs = require('fs');

// File path to the text file containing suspicious words
const filePath = 'suspicious_words.txt';
const suspiciousWords = getWordsFromFile(filePath);

// Middleware to parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (like your HTML file)
app.use(express.static('public'));

// Connect to the SQLite database
const db = new sqlite3.Database('users.db', (err) => {
  if (err) {
    console.error('Error connecting to database:', err.message);
  } else {
    console.log('Connected to the database.');
    // Create users table if it doesn't exist and insert sample values
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT,
      password TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      } else {
        console.log('Users table created successfully.');
        // Insert sample values into the users table
        const sampleValues = [
          { username: 'user1', password: 'password1' },
          { username: 'user2', password: 'password2' },
          { username: 'user3', password: 'password3' }
        ];
        const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
        sampleValues.forEach(({ username, password }) => {
          db.run(insertQuery, [username, password], (err) => {
            if (err) {
              console.error('Error inserting sample values:', err.message);
            } else {
              console.log(`Inserted user: ${username}`);
            }
          });
        });
      }
    });
  }
});

// Route to handle the form submission
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Query the database to check if the username and password match
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) {
      // Handle error
      console.error('Error querying database:', err);
      res.status(500).send('Internal Server Error');
      return;
    }

    console.log('Query result:', row);
    console.log('Username received', username)

    if(containsWord(username, suspiciousWords)) {
      console.log('Nice attempt. SQL Injection Detected')
      res.send('Nice attempt. SQL Injection Detected');
    } else {
      if (row) {
        // User with matching credentials found
        console.log('Login successful!');
        res.send('Login successful!');
      } else {
        // No user found with matching credentials
        console.log('Login failed. Invalid username or password.');
        res.status(401).send('Login failed. Invalid username or password.');
      }
    }
    
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Function to read words from a text file and return them as an array
function getWordsFromFile(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return data.split(/\r?\n/); // Split the contents by new line to get an array of words
  } catch (err) {
    console.error('Error reading the file:', err);
    return [];
  }
}

// Function to check if username contains any word from the list
function containsWord(username, words) {
  for (const word of words) {
    if (username.includes(word)) {
      return true;
    }
  }
  return false;
}
