const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
// const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

const JWT_SECRET = process.env.JWT_SECRET;


// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('.'));


app.use((req, res, next) => {
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('Content-Security-Policy-Report-Only');
  next();
});


// app.use(helmet({
//   contentSecurityPolicy: {
//     directives: {
//       defaultSrc: ["'self'"],
//       styleSrc: [
//         "'self'",
//         "'unsafe-inline'",
//         "https://cdn.tailwindcss.com",
//         "https://cdnjs.cloudflare.com"
//       ],
//       scriptSrc: [
//         "'self'",
//         "'unsafe-inline'",
//         "https://cdn.tailwindcss.com"
//       ],
//       fontSrc: [
//         "'self'",
//         "https://cdnjs.cloudflare.com",
//         "data:"
//       ],
//       imgSrc: [
//         "'self'",
//         "data:",
//         "https:",
//         "http:",
//         "https://images.unsplash.com"
//       ],
//       connectSrc: [
//         "'self'",
//         "https://gutendex.com"  // Add this line
//       ],
//       objectSrc: ["'none'"],
//       mediaSrc: ["'self'"],
//       frameSrc: ["'none'"],
//     },
//   },
//   crossOriginEmbedderPolicy: false
// }));


// Database setup
const db = new sqlite3.Database('ebook_users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create single users table 
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        address TEXT,
        city TEXT,
        postcode TEXT,
        country TEXT,
        iban TEXT,
        marketing BOOLEAN DEFAULT 0,
        terms BOOLEAN DEFAULT 0,
        lp_completed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
    if (err) {
      console.error('Error creating users table:', err.message);
    } else {
      console.log('Users table ready.');
    }
  });
});


db.serialize(() => {
  db.run(`ALTER TABLE users ADD COLUMN promotion BOOLEAN DEFAULT 0`, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding promotion column:', err.message);
    } else {
      console.log('Promotion column ready.');
    }
  });
});


// Middleware to verify JWT token with redirect (for HTML pages)
function verifyTokenWithRedirect(req, res, next) {
  const token = req.cookies.authToken;

  console.log('Verifying token for page access:', token ? 'Token exists' : 'No token');

  if (!token) {
    console.log('No token found, redirecting to login');
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    console.log('Token verified for user:', decoded.userId);
    next();
  } catch (error) {
    console.error('Token verification failed, redirecting to login:', error.message);
    return res.redirect('/login');
  }
}


// Middleware to verify JWT token (for API endpoints)
function verifyToken(req, res, next) {
  const token = req.cookies.authToken;

  console.log('Verifying token for API:', token ? 'Token exists' : 'No token');

  if (!token) {
    return res.status(401).json({ authenticated: false });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    console.log('Token verified for user:', decoded.userId);
    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    return res.status(401).json({ authenticated: false });
  }
}

// Routes for serving HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/registration', (req, res) => {
  res.sendFile(path.join(__dirname, 'registration.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/subscription', verifyTokenWithRedirect, (req, res) => {
  res.sendFile(path.join(__dirname, 'subscription.html'));
});

app.get('/lp', verifyTokenWithRedirect, (req, res) => {
  res.sendFile(path.join(__dirname, 'lp.html'));
});

app.get('/lib', verifyTokenWithRedirect, (req, res) => {
  res.sendFile(path.join(__dirname, 'lib.html'));
});

app.get('/profile', verifyTokenWithRedirect, (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});



// Registration endpoint 
app.post('/api/register', async (req, res) => {
  const { email, password, 'first-name': firstName, 'last-name': lastName, address, city, postcode, country, iban, marketing, terms } = req.body;

  // Validate required fields
  if (!email || !password) {
    return res.status(400).json({ error: 'Email und Passwort sind erforderlich' });
  }

  if (!firstName || !lastName) {
    return res.status(400).json({ error: 'Vor- und Nachname sind erforderlich' });
  }

  // Check if user already exists
  db.get('SELECT id, email FROM users WHERE email = ?', [email], async (err, existingUser) => {
    if (err) {
      console.error('Database error during user check:', err);
      return res.status(500).json({ error: 'Server Fehler' });
    }

    if (existingUser) {
      console.log('User already exists:', email);
      return res.status(400).json({
        error: 'Ein Konto mit dieser E-Mail-Adresse existiert bereits. Bitte melden Sie sich an oder verwenden Sie eine andere E-Mail-Adresse.',
        userExists: true
      });
    }

    // User doesn't exist, proceed with registration
    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        'INSERT INTO users (email, password, first_name, last_name, address, city, postcode, country, iban, marketing, promotion, terms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [email, hashedPassword, firstName, lastName, address, city, postcode, country, iban, marketing ? 1 : 0, 0, terms ? 1 : 0],
        function (err) {
          if (err) {
            console.error('Database error during registration:', err);
            if (err.code === 'SQLITE_CONSTRAINT') {
              return res.status(400).json({ error: 'Email bereits registriert' });
            }
            return res.status(500).json({ error: 'Registrierung fehlgeschlagen' });
          }

          console.log('User registered successfully with ID:', this.lastID);

          // Create JWT token for new user
          const token = jwt.sign(
            {
              userId: this.lastID,
              email: email
            },
            JWT_SECRET,
            { expiresIn: '7d' }
          );

          // Set HTTP-only cookie
          res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
          });

          res.json({ success: true, message: 'Registrierung erfolgreich' });
        }
      );
    } catch (error) {
      console.error('Server error during password hashing:', error);
      res.status(500).json({ error: 'Server Fehler' });
    }
  });
});


// Login endpoint
app.post('/api/login', async (req, res) => {
  console.log('Login attempt received:', req.body);

  const { email, password } = req.body;

  if (!email || !password) {
    console.log('Missing email or password');
    return res.status(400).json({ error: 'Email und Passwort sind erforderlich' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Server Fehler' });
    }

    console.log('User found:', user ? 'Yes' : 'No');

    if (!user) {
      console.log('User not found for email:', email);
      return res.status(400).json({ error: 'Ungültige Anmeldedaten' });
    }

    try {
      const isValidPassword = await bcrypt.compare(password, user.password);
      console.log('Password valid:', isValidPassword);

      if (!isValidPassword) {
        console.log('Invalid password for user:', email);
        return res.status(400).json({ error: 'Ungültige Anmeldedaten' });
      }

      // Create JWT token
      const token = jwt.sign(
        {
          userId: user.id,
          email: user.email
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      // Set HTTP-only cookie
      res.cookie('authToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        sameSite: 'lax'
      });

      console.log('Login successful, JWT token created for user:', user.id);
      res.json({ success: true, message: 'Anmeldung erfolgreich' });

    } catch (bcryptError) {
      console.error('Bcrypt error:', bcryptError);
      return res.status(500).json({ error: 'Server Fehler' });
    }
  });
});

// Check auth endpoint
app.get('/api/check-auth', verifyToken, (req, res) => {
  console.log('Auth check passed for user:', req.user.userId);
  res.json({
    authenticated: true,
    userId: req.user.userId,
    email: req.user.email
  });
});

// Check if email exists endpoint (for frontend validation)
app.post('/api/check-email', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email ist erforderlich' });
  }

  db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      console.error('Database error during email check:', err);
      return res.status(500).json({ error: 'Server Fehler' });
    }

    res.json({ exists: !!user });
  });
});

// LP registration endpoint 
app.post('/api/lp-register', async (req, res) => {
  const { firstname, lastname, email, address, city, postcode, country, iban, promotions, terms, password } = req.body;

  // Check if user is authenticated
  const token = req.cookies.authToken;
  let userId = null;
  let isExistingUser = false;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
      isExistingUser = true;
      console.log('LP registration for existing user:', userId);
    } catch (error) {
      console.log('Invalid token, treating as new user');
    }
  }

  if (isExistingUser && userId) {
    // UPDATE existing user
    db.run(
      `UPDATE users SET 
              first_name = COALESCE(?, first_name),
              last_name = COALESCE(?, last_name),
              address = COALESCE(?, address),
              city = COALESCE(?, city),
              postcode = COALESCE(?, postcode),
              country = COALESCE(?, country),
              iban = COALESCE(?, iban),
              promotion = COALESCE(?, promotion),
              terms = COALESCE(?, terms),
              lp_completed = 1,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?`,
      [firstname, lastname, address, city, postcode, country, iban, promotions ? 1 : 0, terms ? 1 : 0, userId],
      function (err) {
        if (err) {
          console.error('LP registration update error:', err);
          return res.status(500).json({ error: 'Speichern fehlgeschlagen' });
        }

        console.log('LP registration updated for existing user:', userId);
        res.json({ success: true, message: 'Daten erfolgreich gespeichert', isUpdate: true });
      }
    );
  } else {
    // CREATE new user
    if (!email || !password) {
      return res.status(400).json({ error: 'Email und Passwort sind für neue Benutzer erforderlich' });
    }

    if (!firstname || !lastname) {
      return res.status(400).json({ error: 'Vor- und Nachname sind erforderlich' });
    }

    // Check if user already exists
    db.get('SELECT id, email FROM users WHERE email = ?', [email], async (err, existingUser) => {
      if (err) {
        console.error('Database error during user check:', err);
        return res.status(500).json({ error: 'Server Fehler' });
      }

      if (existingUser) {
        console.log('User already exists:', email);
        return res.status(400).json({
          error: 'Ein Konto mit dieser E-Mail-Adresse existiert bereits. Bitte melden Sie sich an.',
          userExists: true
        });
      }

      // Create new user
      try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
          'INSERT INTO users (email, password, first_name, last_name, address, city, postcode, country, iban, promotion, terms, lp_completed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [email, hashedPassword, firstname, lastname, address, city, postcode, country, iban, promotions ? 1 : 0, terms ? 1 : 0, 1],
          function (err) {
            if (err) {
              console.error('Database error during LP registration:', err);
              if (err.code === 'SQLITE_CONSTRAINT') {
                return res.status(400).json({ error: 'Email bereits registriert' });
              }
              return res.status(500).json({ error: 'Registrierung fehlgeschlagen' });
            }

            console.log('New user registered via LP with ID:', this.lastID);

            // Create JWT token for new user
            const token = jwt.sign(
              {
                userId: this.lastID,
                email: email
              },
              JWT_SECRET,
              { expiresIn: '7d' }
            );

            // Set HTTP-only cookie
            res.cookie('authToken', token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
              sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
            });

            res.json({ success: true, message: 'Registrierung erfolgreich', isUpdate: false });
          }
        );
      } catch (error) {
        console.error('Server error during password hashing:', error);
        res.status(500).json({ error: 'Server Fehler' });
      }
    });
  }
});

// Get user profile endpoint
app.get('/api/profile', verifyToken, (req, res) => {
  db.get('SELECT id, email, first_name, last_name, address, city, postcode, country, marketing, promotion, lp_completed, created_at FROM users WHERE id = ?',
    [req.user.userId],
    (err, user) => {
      if (err) {
        console.error('Profile fetch error:', err);
        return res.status(500).json({ error: 'Profil konnte nicht geladen werden' });
      }

      if (!user) {
        return res.status(404).json({ error: 'Benutzer nicht gefunden' });
      }

      console.log('Profile loaded for user:', req.user.userId);
      res.json({ success: true, user });
    }
  );
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  res.clearCookie('authToken');
  console.log('User logged out');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});
