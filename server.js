const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT;
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(bodyParser.json()); 

const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Error de conexión a MongoDB:'));
db.once('open', () => {
  console.log('Conectado a MongoDB');
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  last_login: { type: Date, default: Date.now },
  role: { type: String, enum: ['user', 'master'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
  name: { type: String, required: true },
  status: { type: String, required: true },
  description: { type: String },
  deadline: { type: Date },
  category: { type: String },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, 
});

const Task = mongoose.model('Task', taskSchema);

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
});

const Group = mongoose.model('Group', groupSchema);

const collaboratorSchema = new mongoose.Schema({
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['admin', 'collaborator'], default: 'collaborator' },
});

const Collaborator = mongoose.model('Collaborator', collaboratorSchema);

const groupTaskSchema = new mongoose.Schema({
  name: { type: String, required: true },
  status: { type: String, required: true },
  description: { type: String },
  deadline: { type: Date },
  category: { type: String },
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
  completedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  completedAt: { type: Date },
});

const GroupTask = mongoose.model('GroupTask', groupTaskSchema);

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Acceso denegado' });

  const JWT_SECRET = process.env.JWT_SECRET;
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

const checkMasterRole = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'master') {
      return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de master.' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '1h',
    });

    user.last_login = Date.now();
    await user.save();
    res.status(200).json({ 
      message: 'Inicio de sesión exitoso', 
      token, 
      userId: user._id,
      role: user.role
    });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/dashboard', authenticateToken, (req, res) => {
  res.json({ message: 'Bienvenido al dashboard', user: req.user });
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { username, email } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, email },
      { new: true }
    ).select('-password');
    
    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    res.status(200).json({ message: 'Perfil actualizado exitosamente', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar el perfil', error: error.message });
  }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/users', authenticateToken, checkMasterRole, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.put('/api/users/:id', authenticateToken, checkMasterRole, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, role } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { username, email, role },
      { new: true }
    ).select('-password');
    
    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    res.status(200).json({ message: 'Usuario actualizado exitosamente', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar el usuario', error: error.message });
  }
});

app.post('/api/create-master', authenticateToken, checkMasterRole, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role: 'master'
    });

    await newUser.save();
    res.status(201).json({ message: 'Usuario master creado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.userId });
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener las tareas', error: error.message });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { name, status, description, deadline, category } = req.body;

    const newTask = new Task({
      name,
      status,
      description,
      deadline,
      category,
      userId: req.user.userId, 
    });

    await newTask.save();
    res.status(201).json({ message: 'Tarea agregada exitosamente', task: newTask });
  } catch (error) {
    res.status(500).json({ message: 'Error al agregar la tarea', error: error.message });
  }
});
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, status, description, deadline, category } = req.body;

    const updatedTask = await Task.findByIdAndUpdate(
      id,
      { name, status, description, deadline, category },
      { new: true }
    );

    if (!updatedTask) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    res.status(200).json({ message: 'Tarea actualizada exitosamente', task: updatedTask });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar la tarea', error: error.message });
  }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;

    const newGroup = new Group({
      name,
      admin: req.user.userId,
    });

    await newGroup.save();

    const newCollaborator = new Collaborator({
      groupId: newGroup._id,
      userId: req.user.userId,
      role: 'admin',
    });

    await newCollaborator.save();

    res.status(201).json({ message: 'Grupo creado exitosamente', group: newGroup });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear el grupo', error: error.message });
  }
});

app.post('/api/groups/:groupId/collaborators', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { email } = req.body;

    const adminCollaborator = await Collaborator.findOne({
      groupId,
      userId: req.user.userId,
      role: 'admin',
    });

    if (!adminCollaborator) {
      return res.status(403).json({ message: 'Solo el administrador puede agregar colaboradores' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const existingCollaborator = await Collaborator.findOne({ groupId, userId: user._id });
    if (existingCollaborator) {
      return res.status(400).json({ message: 'El usuario ya es colaborador en este grupo' });
    }

    const newCollaborator = new Collaborator({
      groupId,
      userId: user._id,
      role: 'collaborator',
    });

    await newCollaborator.save();
    res.status(201).json({ message: 'Colaborador añadido exitosamente', collaborator: newCollaborator });
  } catch (error) {
    res.status(500).json({ message: 'Error al añadir colaborador', error: error.message });
  }
});

app.get('/api/groups/:groupId/collaborators', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;

    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }

    const collaborators = await Collaborator.find({ groupId }).populate('userId', 'username email');
    res.status(200).json(collaborators);
  } catch (error) {
    console.error('Error al obtener los colaboradores:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    
    const groups = await Collaborator.find({ userId: req.user.userId })
      .populate('groupId')
      .populate({
        path: 'groupId',
        populate: {
          path: 'admin',
          select: 'username', 
        },
      });

    res.status(200).json(groups);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los grupos', error: error.message });
  }
});

app.post('/api/groups/:groupId/tasks', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name, status, description, deadline, category, assignedTo } = req.body;

    const collaborator = await Collaborator.findOne({ groupId, userId: req.user.userId });
    if (!collaborator) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }
    if (assignedTo) {
      const assignedCollaborator = await Collaborator.findOne({ groupId, userId: assignedTo });
      if (!assignedCollaborator) {
        return res.status(400).json({ message: 'El usuario asignado no es un colaborador del grupo' });
      }
    }

    const newGroupTask = new GroupTask({
      name,
      status,
      description,
      deadline,
      category,
      groupId,
      createdBy: req.user.userId,
      assignedTo,
    });

    await newGroupTask.save();
    res.status(201).json({ message: 'Tarea creada exitosamente', task: newGroupTask });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear la tarea', error: error.message });
  }
});

app.get('/api/groups/:groupId/tasks', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;

    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }

    const collaborator = await Collaborator.findOne({ groupId, userId: req.user.userId });
    if (!collaborator) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }

    let tasks;
    if (collaborator.role === 'admin') {
      tasks = await GroupTask.find({ groupId }).populate('createdBy', 'username').populate('assignedTo', 'username');
    } else {
      tasks = await GroupTask.find({ groupId, $or: [{ assignedTo: req.user.userId }, { createdBy: req.user.userId }] })
        .populate('createdBy', 'username')
        .populate('assignedTo', 'username');
    }

    res.status(200).json(tasks);
  } catch (error) {
    console.error('Error en el servidor:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.put('/api/groups/:groupId/tasks/:taskId/complete', authenticateToken, async (req, res) => {
  try {
    const { groupId, taskId } = req.params;

    const collaborator = await Collaborator.findOne({ groupId, userId: req.user.userId });
    if (!collaborator) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }

    const task = await GroupTask.findById(taskId);
    if (!task) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    task.status = 'completada';
    task.completedBy = req.user.userId;
    task.completedAt = new Date();

    await task.save();
    res.status(200).json({ message: 'Tarea completada exitosamente', task });
  } catch (error) {
    res.status(500).json({ message: 'Error al completar la tarea', error: error.message });
  }
});

app.put('/api/groups/:groupId/tasks/:taskId', authenticateToken, async (req, res) => {
  try {
    const { groupId, taskId } = req.params;
    const { name, status, description, deadline, category, assignedTo } = req.body;

    const collaborator = await Collaborator.findOne({ groupId, userId: req.user.userId });
    if (!collaborator) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }

    const updatedTask = await GroupTask.findByIdAndUpdate(
      taskId,
      { name, status, description, deadline, category, assignedTo },
      { new: true }
    );

    if (!updatedTask) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    res.status(200).json({ message: 'Tarea actualizada exitosamente', task: updatedTask });
  } catch (error) {
    console.error('Error al actualizar la tarea:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});