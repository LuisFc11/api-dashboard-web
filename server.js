// server.js (actualizado con permisos)
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const mqtt = require('mqtt');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Initialize Express app and HTTP server
const app = express();
const server = http.createServer(app);

// Configure CORS with restricted origin
const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Middleware
app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000' }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Conectado a MongoDB'))
  .catch(err => console.error('Error en MongoDB:', err.message));

// Permissions Schema
const PermissionsSchema = new mongoose.Schema({
  dashboard: { type: Boolean, default: false },
  historial: { type: Boolean, default: false },
  graficos: { type: Boolean, default: false },
  camara: { type: Boolean, default: false },
  productos: { type: Boolean, default: false },
  usuarios: { type: Boolean, default: false },
  configuracion: { type: Boolean, default: false },
});

// User Schema with Role and Permissions
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  role: { type: String, enum: ['admin', 'staff'], default: 'staff' },
  permissions: PermissionsSchema
});
const User = mongoose.model('User', UserSchema, 'usuarios');

// Product Schema
const ProductSchema = new mongoose.Schema({
  codeqr: { type: String, required: true },
  nombre: { type: String, required: true },
  descripcion: { type: String },
  precio: { type: Number, required: true },
  stock: { type: Number, default: 0 },
  category: { type: String, default: 'General' },
  imageUrl: { type: String }
}, { timestamps: true });

const Product = mongoose.model('Product', ProductSchema, 'productos');

// Reporte Schema
const ReporteSchema = new mongoose.Schema({
  message: String,
  timestamp: { type: Date, default: Date.now }
});
const Reporte = mongoose.model('Reporte', ReporteSchema);

// Signup Endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, email, role = 'staff' } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Usuario o email ya existe' });
    }

    const existingAdmin = await User.findOne({ role: 'admin' });
    if (role === 'admin' && existingAdmin) {
      return res.status(403).json({ error: 'Ya existe un admin. Usa el dashboard para agregar staff.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const defaultPermissions = role === 'admin' ? {
      dashboard: true,
      historial: true,
      graficos: true,
      camara: true,
      productos: true,
      usuarios: true,
      configuracion: true,
    } : {
      dashboard: false,
      historial: false,
      graficos: false,
      camara: false,
      productos: false,
      usuarios: false,
      configuracion: false,
    };
    const newUser = new User({ username, password: hashedPassword, email, role, permissions: defaultPermissions });
    await newUser.save();

    res.status(201).json({ message: 'Usuario creado exitosamente', role });
  } catch (err) {
    console.error('Error al crear usuario:', err.message);
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, email: user.email, role: user.role, permissions: user.permissions },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, username: user.username, email: user.email, role: user.role, permissions: user.permissions });
  } catch (err) {
    console.error('Error al iniciar sesión:', err.message);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Update Profile Endpoint
app.post('/api/update-profile', async (req, res) => {
  try {
    const { username, email } = req.body;
    const user = await User.findOne({ username: req.body.username });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    let updated = false;
    if (username && username !== user.username) {
      const existingUser = await User.findOne({ username });
      if (existingUser) return res.status(400).json({ error: 'Nombre de usuario ya existe' });
      user.username = username;
      updated = true;
    }
    if (email && email !== user.email) {
      const existingEmail = await User.findOne({ email });
      if (existingEmail) return res.status(400).json({ error: 'Email ya existe' });
      user.email = email;
      updated = true;
    }

    if (updated) {
      await user.save();
    }

    res.json({ message: 'Perfil actualizado', username: user.username, email: user.email });
  } catch (err) {
    console.error('Error al actualizar perfil:', err.message);
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});
// Ruta raíz para confirmar que el servidor está corriendo
app.get('/', (req, res) => {
  res.send('Servidor backend corriendo correctamente. Usa /api/ para los endpoints.');
});

// Report Endpoint
app.get('/api/reports', async (req, res) => {
  try {
    const reports = await Reporte.find().sort({ timestamp: -1 }).limit(100);
    res.json(reports);
  } catch (err) {
    console.error('Error al obtener reports:', err.message);
    res.status(500).json({ error: 'Error al obtener datos' });
  }
});

// Product Endpoints
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    console.log('Productos enviados:', products);
    res.json(products);
  } catch (err) {
    console.error('Error al obtener productos:', err.message);
    res.status(500).json({ error: 'Error al obtener productos' });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { codeqr, nombre, descripcion, precio, stock, category, imageUrl } = req.body;
    console.log('Datos recibidos para agregar:', req.body);
    if (!codeqr || !nombre || !precio) {
      return res.status(400).json({ error: 'Campos requeridos faltantes (codeqr, nombre, precio)' });
    }
    const newProduct = new Product({ codeqr, nombre, descripcion, precio, stock, category: category || 'General', imageUrl });
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    console.error('Error al agregar producto:', err.message);
    res.status(500).json({ error: 'Error al agregar producto' });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    const updatedProduct = await Product.findByIdAndUpdate(id, updateData, { new: true });
    if (!updatedProduct) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    res.json(updatedProduct);
  } catch (err) {
    console.error('Error al actualizar producto:', err.message);
    res.status(500).json({ error: 'Error al actualizar producto' });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedProduct = await Product.findByIdAndDelete(id);
    if (!deletedProduct) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    res.json({ message: 'Producto eliminado' });
  } catch (err) {
    console.error('Error al eliminar producto:', err.message);
    res.status(500).json({ error: 'Error al eliminar producto' });
  }
});

// User Endpoints
app.get('/api/users', async (req, res) => {
  try {
    console.log('Solicitud GET a /api/users');
    const users = await User.find({}, { password: 0 });
    console.log('Usuarios encontrados:', users);
    res.json(users);
  } catch (err) {
    console.error('Error al obtener usuarios:', err.message);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const { username, email, role, password } = req.body;
    console.log('Datos recibidos para agregar usuario:', req.body);
    if (!username || !email || !role) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Usuario o email ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password || 'default123', 10);
    const defaultPermissions = role === 'admin' ? {
      dashboard: true,
      historial: true,
      graficos: true,
      camara: true,
      productos: true,
      usuarios: true,
      configuracion: true,
    } : {
      dashboard: false,
      historial: false,
      graficos: false,
      camara: false,
      productos: false,
      usuarios: false,
      configuracion: false,
    };
    const newUser = new User({ username, email, password: hashedPassword, role, permissions: defaultPermissions });
    await newUser.save();

    res.status(201).json({ message: 'Usuario creado exitosamente', user: { id: newUser._id, username, email, role, permissions: newUser.permissions } });
  } catch (err) {
    console.error('Error al agregar usuario:', err.message);
    res.status(500).json({ error: 'Error al agregar usuario' });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, role, password, permissions } = req.body;
    console.log('Datos recibidos para actualizar usuario:', { id, username, email, role, password, permissions });

    const user = await User.findById(id);
    if (!user) {
      console.log('Usuario no encontrado con ID:', id);
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (username && username !== user.username) {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: 'Nombre de usuario ya existe' });
      }
      user.username = username;
    }
    if (email && email !== user.email) {
      const existingEmail = await User.findOne({ email });
      if (existingEmail) {
        return res.status(400).json({ error: 'Email ya existe' });
      }
      user.email = email;
    }
    if (role) {
      user.role = role;
    }
    if (password) {
      user.password = await bcrypt.hash(password, 10);
    }
    if (permissions) {
      user.permissions = permissions;
    }

    await user.save();
    console.log('Usuario actualizado:', user);
    res.json({ message: 'Usuario actualizado exitosamente', user: { id: user._id, username: user.username, email: user.email, role: user.role, permissions: user.permissions } });
  } catch (err) {
    console.error('Error al actualizar usuario:', err.message);
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    console.log('Solicitud DELETE a /api/users/:id');
    const { id } = req.params;
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      console.log('Usuario no encontrado con ID:', id);
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    console.error('Error al eliminar usuario:', err.message);
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// Configuración del cliente MQTT
const mqttOptions = {
  port: parseInt(process.env.MQTT_PORT) || 1883,
  username: process.env.MQTT_USER || undefined,
  password: process.env.MQTT_PASSWORD || undefined
};
const mqttClient = mqtt.connect(process.env.MQTT_BROKER || 'mqtt://localhost:1883', mqttOptions);

mqttClient.on('connect', () => {
  console.log('Conectado a MQTT');
  mqttClient.subscribe('home/alarm/status', (err) => {
    if (!err) console.log('Suscrito a home/alarm/status');
    else console.error('Error al suscribirse a home/alarm/status:', err.message);
  });
  mqttClient.subscribe('home/alarm/control', (err) => {
    if (!err) console.log('Suscrito a home/alarm/control');
    else console.error('Error al suscribirse a home/alarm/control:', err.message);
  });
});

mqttClient.on('error', (err) => {
  console.error('Error en conexión MQTT:', err.message);
});

mqttClient.on('message', (topic, message) => {
  console.log('Mensaje MQTT recibido:', topic, message.toString());
  try {
    const data = JSON.parse(message.toString());
    const newReporte = new Reporte({ message: JSON.stringify(data) });
    newReporte.save()
      .then(() => {
        console.log(`Guardado en Reporte desde ${topic}: ${message}`);
        io.emit('alarmNotification', { message: JSON.stringify(data), timestamp: new Date() });
      })
      .catch(err => console.error('Error al guardar en Reporte:', err.message));
  } catch (err) {
    console.warn('Mensaje no es JSON válido, guardando como texto:', message.toString());
    const newReporte = new Reporte({ message: message.toString() });
    newReporte.save()
      .then(() => {
        console.log(`Guardado en Reporte como texto desde ${topic}: ${message}`);
        io.emit('alarmNotification', { message: message.toString(), timestamp: new Date() });
      })
      .catch(err => console.error('Error al guardar en Reporte:', err.message));
  }
});

// Socket.io conexión
io.on('connection', (socket) => {
  console.log('Cliente conectado:', socket.id);

  socket.on('disarmAlarm', (data) => {
    console.log('Solicitud de desactivación recibida:', data);
    try {
      const { password } = data;
      if (!password || typeof password !== 'string' || password.length > 20) {
        console.error('Contraseña inválida o no proporcionada');
        io.emit('alarmNotification', {
          message: JSON.stringify({ error: 'Invalid or missing password' }),
          timestamp: new Date(),
        });
        return;
      }

      const mqttMessage = JSON.stringify({ password });
      console.log('Publicando mensaje MQTT:', mqttMessage);
      mqttClient.publish('home/alarm/control', mqttMessage, { qos: 1 }, (err) => {
        if (err) {
          console.error('Error al publicar MQTT:', err.message);
          io.emit('alarmNotification', {
            message: JSON.stringify({ error: 'Failed to publish MQTT message' }),
            timestamp: new Date(),
          });
        } else {
          console.log('Mensaje MQTT publicado exitosamente');
        }
      });
    } catch (err) {
      console.error('Error al procesar disarmAlarm:', err.message);
      io.emit('alarmNotification', {
        message: JSON.stringify({ error: 'Invalid request format' }),
        timestamp: new Date(),
      });
    }
  });

  socket.on('activateAlarm', () => {
    console.log('Solicitud de activación recibida');
    const mqttMessage = JSON.stringify({ action: 'activate' });
    mqttClient.publish('home/alarm/control', mqttMessage, { qos: 1 }, (err) => {
      if (err) {
        console.error('Error al publicar MQTT:', err.message);
        io.emit('alarm interspersedNotification', {
          message: JSON.stringify({ error: 'Failed to publish MQTT message' }),
          timestamp: new Date(),
        });
      } else {
        console.log('Mensaje de activación MQTT publicado exitosamente');
      }
    });
  });

  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

// Iniciar servidor
const PORT = parseInt(process.env.SERVER_PORT) || 5000;
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});