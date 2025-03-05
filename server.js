const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(bodyParser.json());

const serviceAccount = {
  "type": "service_account",
  "project_id": "backendtasksmanager",
  "private_key_id": "1dae0d35db29eaaf6e77f8ebf9f79317eb33a400",
  "private_key": process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : "",
  "client_email": "firebase-adminsdk-fbsvc@backendtasksmanager.iam.gserviceaccount.com",
  "client_id": "117461456523032019041",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40backendtasksmanager.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

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
    const userRef = db.collection('users').doc(req.user.userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || userDoc.data().role !== 'master') {
      return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de master.' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
};

app.get('/', (req, res) => {
  res.json({ message: 'API de TaskApp Manager funcionando correctamente' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();
    
    if (!snapshot.empty) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      username,
      email,
      password: hashedPassword,
      last_login: admin.firestore.Timestamp.now(),
      role: 'user'
    };

    const docRef = await usersRef.add(newUser);
    res.status(201).json({ message: 'Usuario registrado exitosamente', userId: docRef.id });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();
    
    if (snapshot.empty) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();

    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ userId: userDoc.id, email: userData.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    await userDoc.ref.update({
      last_login: admin.firestore.Timestamp.now()
    });

    res.status(200).json({ 
      message: 'Inicio de sesión exitoso', 
      token, 
      userId: userDoc.id,
      role: userData.role
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
    
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    await userRef.update({ username, email });
    
    const updatedUserDoc = await userRef.get();
    const userData = updatedUserDoc.data();
    
    const userWithoutPassword = {
      id: updatedUserDoc.id,
      username: userData.username,
      email: userData.email,
      role: userData.role,
      last_login: userData.last_login
    };
    
    res.status(200).json({ message: 'Perfil actualizado exitosamente', user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar el perfil', error: error.message });
  }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.user.userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const userData = userDoc.data();
    const userWithoutPassword = {
      id: userDoc.id,
      username: userData.username,
      email: userData.email,
      role: userData.role,
      last_login: userData.last_login
    };
    
    res.status(200).json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/users', authenticateToken, checkMasterRole, async (req, res) => {
  try {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.get();
    
    const users = [];
    snapshot.forEach(doc => {
      const userData = doc.data();
      users.push({
        id: doc.id,
        username: userData.username,
        email: userData.email,
        role: userData.role,
        last_login: userData.last_login
      });
    });
    
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.put('/api/users/:id', authenticateToken, checkMasterRole, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, role } = req.body;
    
    const userRef = db.collection('users').doc(id);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    await userRef.update({ username, email, role });
    
    const updatedUserDoc = await userRef.get();
    const userData = updatedUserDoc.data();
    
    const userWithoutPassword = {
      id: updatedUserDoc.id,
      username: userData.username,
      email: userData.email,
      role: userData.role,
      last_login: userData.last_login
    };
    
    res.status(200).json({ message: 'Usuario actualizado exitosamente', user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar el usuario', error: error.message });
  }
});

app.post('/api/create-master', authenticateToken, checkMasterRole, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();
    
    if (!snapshot.empty) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      username,
      email,
      password: hashedPassword,
      last_login: admin.firestore.Timestamp.now(),
      role: 'master'
    };

    await usersRef.add(newUser);
    res.status(201).json({ message: 'Usuario master creado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const tasksRef = db.collection('tasks');
    const snapshot = await tasksRef.where('userId', '==', req.user.userId).get();
    
    const tasks = [];
    snapshot.forEach(doc => {
      tasks.push({
        id: doc.id,
        ...doc.data()
      });
    });
    
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener las tareas', error: error.message });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { name, status, description, deadline, category } = req.body;

    const newTask = {
      name,
      status,
      description,
      deadline: deadline ? new Date(deadline) : null,
      category,
      userId: req.user.userId,
    };

    const docRef = await db.collection('tasks').add(newTask);
    const taskWithId = { id: docRef.id, ...newTask };
    
    res.status(201).json({ message: 'Tarea agregada exitosamente', task: taskWithId });
  } catch (error) {
    res.status(500).json({ message: 'Error al agregar la tarea', error: error.message });
  }
});

app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, status, description, deadline, category } = req.body;

    const taskRef = db.collection('tasks').doc(id);
    const taskDoc = await taskRef.get();
    
    if (!taskDoc.exists) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }
    
    const updateData = {
      name,
      status,
      description,
      category
    };
    
    if (deadline) {
      updateData.deadline = new Date(deadline);
    }
    
    await taskRef.update(updateData);
    
    const updatedTaskDoc = await taskRef.get();
    const updatedTask = {
      id: updatedTaskDoc.id,
      ...updatedTaskDoc.data()
    };
    
    res.status(200).json({ message: 'Tarea actualizada exitosamente', task: updatedTask });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar la tarea', error: error.message });
  }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;

    const newGroup = {
      name,
      admin: req.user.userId,
      createdAt: admin.firestore.Timestamp.now()
    };

    const groupRef = await db.collection('groups').add(newGroup);
    const groupWithId = { id: groupRef.id, ...newGroup };

    const newCollaborator = {
      groupId: groupRef.id,
      userId: req.user.userId,
      role: 'admin'
    };

    await db.collection('collaborators').add(newCollaborator);

    res.status(201).json({ message: 'Grupo creado exitosamente', group: groupWithId });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear el grupo', error: error.message });
  }
});

app.post('/api/groups/:groupId/collaborators', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { email } = req.body;

    const collaboratorsRef = db.collection('collaborators');
    const adminSnapshot = await collaboratorsRef
      .where('groupId', '==', groupId)
      .where('userId', '==', req.user.userId)
      .where('role', '==', 'admin')
      .get();

    if (adminSnapshot.empty) {
      return res.status(403).json({ message: 'Solo el administrador puede agregar colaboradores' });
    }

    const usersRef = db.collection('users');
    const userSnapshot = await usersRef.where('email', '==', email).get();
    
    if (userSnapshot.empty) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const userDoc = userSnapshot.docs[0];
    
    const existingCollabSnapshot = await collaboratorsRef
      .where('groupId', '==', groupId)
      .where('userId', '==', userDoc.id)
      .get();
      
    if (!existingCollabSnapshot.empty) {
      return res.status(400).json({ message: 'El usuario ya es colaborador en este grupo' });
    }

    const newCollaborator = {
      groupId,
      userId: userDoc.id,
      role: 'collaborator'
    };

    const collabRef = await collaboratorsRef.add(newCollaborator);
    const collaboratorWithId = { id: collabRef.id, ...newCollaborator };
    
    res.status(201).json({ message: 'Colaborador añadido exitosamente', collaborator: collaboratorWithId });
  } catch (error) {
    res.status(500).json({ message: 'Error al añadir colaborador', error: error.message });
  }
});

app.get('/api/groups/:groupId/collaborators', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;

    const groupRef = db.collection('groups').doc(groupId);
    const groupDoc = await groupRef.get();
    
    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }

    const collaboratorsRef = db.collection('collaborators');
    const snapshot = await collaboratorsRef.where('groupId', '==', groupId).get();
    
    const usersRef = db.collection('users');
    const collaborators = [];
    
    for (const doc of snapshot.docs) {
      const collabData = doc.data();
      const userDoc = await usersRef.doc(collabData.userId).get();
      
      if (userDoc.exists) {
        const userData = userDoc.data();
        collaborators.push({
          id: doc.id,
          userId: {
            id: userDoc.id,
            username: userData.username,
            email: userData.email
          },
          role: collabData.role,
          groupId: collabData.groupId
        });
      }
    }
    
    res.status(200).json(collaborators);
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const collaboratorsRef = db.collection('collaborators');
    const collabSnapshot = await collaboratorsRef.where('userId', '==', req.user.userId).get();
    
    const groupsRef = db.collection('groups');
    const usersRef = db.collection('users');
    
    const groups = [];
    
    for (const doc of collabSnapshot.docs) {
      const collabData = doc.data();
      const groupDoc = await groupsRef.doc(collabData.groupId).get();
      
      if (groupDoc.exists) {
        const groupData = groupDoc.data();
        const adminDoc = await usersRef.doc(groupData.admin).get();
        
        let adminUsername = "Desconocido";
        if (adminDoc.exists) {
          adminUsername = adminDoc.data().username;
        }
        
        groups.push({
          id: doc.id,
          groupId: {
            id: groupDoc.id,
            name: groupData.name,
            admin: {
              id: groupData.admin,
              username: adminUsername
            },
            createdAt: groupData.createdAt
          },
          role: collabData.role,
          userId: req.user.userId
        });
      }
    }
    
    res.status(200).json(groups);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener los grupos', error: error.message });
  }
});

app.post('/api/groups/:groupId/tasks', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name, status, description, deadline, category, assignedTo } = req.body;

    const collaboratorsRef = db.collection('collaborators');
    const collabSnapshot = await collaboratorsRef
      .where('groupId', '==', groupId)
      .where('userId', '==', req.user.userId)
      .get();

    if (collabSnapshot.empty) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }
    
    if (assignedTo) {
      const assignedCollabSnapshot = await collaboratorsRef
        .where('groupId', '==', groupId)
        .where('userId', '==', assignedTo)
        .get();
        
      if (assignedCollabSnapshot.empty) {
        return res.status(400).json({ message: 'El usuario asignado no es un colaborador del grupo' });
      }
    }

    const newGroupTask = {
      name,
      status,
      description,
      deadline: deadline ? new Date(deadline) : null,
      category,
      groupId,
      createdBy: req.user.userId,
      assignedTo,
      completedBy: null,
      completedAt: null
    };

    const taskRef = await db.collection('groupTasks').add(newGroupTask);
    const taskWithId = { id: taskRef.id, ...newGroupTask };
    
    res.status(201).json({ message: 'Tarea creada exitosamente', task: taskWithId });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear la tarea', error: error.message });
  }
});

app.get('/api/groups/:groupId/tasks', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;

    const groupRef = db.collection('groups').doc(groupId);
    const groupDoc = await groupRef.get();
    
    if (!groupDoc.exists) {
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }

    const collaboratorsRef = db.collection('collaborators');
    const collabSnapshot = await collaboratorsRef
      .where('groupId', '==', groupId)
      .where('userId', '==', req.user.userId)
      .get();

    if (collabSnapshot.empty) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }
    
    const collabData = collabSnapshot.docs[0].data();
    const tasksRef = db.collection('groupTasks');
    let tasksSnapshot;
    
    if (collabData.role === 'admin') {
      tasksSnapshot = await tasksRef.where('groupId', '==', groupId).get();
    } else {
      tasksSnapshot = await tasksRef
        .where('groupId', '==', groupId)
        .where(admin.firestore.FieldPath.documentId(), 'in', [
          admin.firestore.FieldPath.documentId().where('assignedTo', '==', req.user.userId),
          admin.firestore.FieldPath.documentId().where('createdBy', '==', req.user.userId)
        ])
        .get();
    }
    
    const usersRef = db.collection('users');
    const tasks = [];
    
    for (const doc of tasksSnapshot.docs) {
      const taskData = doc.data();
      
      let createdByUser = null;
      if (taskData.createdBy) {
        const createdByDoc = await usersRef.doc(taskData.createdBy).get();
        if (createdByDoc.exists) {
          createdByUser = {
            id: createdByDoc.id,
            username: createdByDoc.data().username
          };
        }
      }
      
      let assignedToUser = null;
      if (taskData.assignedTo) {
        const assignedToDoc = await usersRef.doc(taskData.assignedTo).get();
        if (assignedToDoc.exists) {
          assignedToUser = {
            id: assignedToDoc.id,
            username: assignedToDoc.data().username
          };
        }
      }
      
      tasks.push({
        id: doc.id,
        ...taskData,
        createdBy: createdByUser,
        assignedTo: assignedToUser
      });
    }
    
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.put('/api/groups/:groupId/tasks/:taskId/complete', authenticateToken, async (req, res) => {
  try {
    const { groupId, taskId } = req.params;

    const collaboratorsRef = db.collection('collaborators');
    const collabSnapshot = await collaboratorsRef
      .where('groupId', '==', groupId)
      .where('userId', '==', req.user.userId)
      .get();

    if (collabSnapshot.empty) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }

    const taskRef = db.collection('groupTasks').doc(taskId);
    const taskDoc = await taskRef.get();
    
    if (!taskDoc.exists) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }

    await taskRef.update({
      status: 'completada',
      completedBy: req.user.userId,
      completedAt: admin.firestore.Timestamp.now()
    });
    
    const updatedTaskDoc = await taskRef.get();
    const updatedTask = {
      id: updatedTaskDoc.id,
      ...updatedTaskDoc.data()
    };
    
    res.status(200).json({ message: 'Tarea completada exitosamente', task: updatedTask });
  } catch (error) {
    res.status(500).json({ message: 'Error al completar la tarea', error: error.message });
  }
});

app.put('/api/groups/:groupId/tasks/:taskId', authenticateToken, async (req, res) => {
  try {
    const { groupId, taskId } = req.params;
    const { name, status, description, deadline, category, assignedTo } = req.body;

    const collaboratorsRef = db.collection('collaborators');
    const collabSnapshot = await collaboratorsRef
      .where('groupId', '==', groupId)
      .where('userId', '==', req.user.userId)
      .get();

    if (collabSnapshot.empty) {
      return res.status(403).json({ message: 'No tienes acceso a este grupo' });
    }

    const taskRef = db.collection('groupTasks').doc(taskId);
    const taskDoc = await taskRef.get();
    
    if (!taskDoc.exists) {
      return res.status(404).json({ message: 'Tarea no encontrada' });
    }
    
    const updateData = {
      name,
      status,
      description,
      category,
      assignedTo
    };
    
    if (deadline) {
      updateData.deadline = new Date(deadline);
    }
    
    await taskRef.update(updateData);
    
    const updatedTaskDoc = await taskRef.get();
    const updatedTask = {
      id: updatedTaskDoc.id,
      ...updatedTaskDoc.data()
    };
    
    res.status(200).json({ message: 'Tarea actualizada exitosamente', task: updatedTask });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});