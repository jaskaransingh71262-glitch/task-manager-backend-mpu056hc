require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
app.options('*', cors());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS','PATCH'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json());
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date() }));

const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const verifyToken = require('./middleware/auth');

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data, error } = await supabase.from('task_manager_users').insert([{ email, password: hashedPassword, name }]);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        const token = jwt.sign({ id: data[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const { data, error } = await supabase.from('task_manager_users').select('*').eq('email', email);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        const isValidPassword = await bcrypt.compare(password, data[0].password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }
        const token = jwt.sign({ id: data[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('task_manager_users').select('*').eq('id', id);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        return res.json(data[0]);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.post('/api/tasks', verifyToken, async (req, res) => {
    try {
        const { title, description } = req.body;
        const { id } = req.user;
        const { data, error } = await supabase.from('task_manager_tasks').insert([{ title, description, user_id: id, completed: false }]);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        return res.status(201).json(data[0]);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.get('/api/tasks', verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('task_manager_tasks').select('*').eq('user_id', id);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        return res.json(data);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.get('/api/tasks/completed', verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('task_manager_tasks').select('*').eq('user_id', id).eq('completed', true);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        return res.json(data);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.get('/api/tasks/incomplete', verifyToken, async (req, res) => {
    try {
        const { id } = req.user;
        const { data, error } = await supabase.from('task_manager_tasks').select('*').eq('user_id', id).eq('completed', false);
        if (error) {
            return res.status(400).json({ error: error.message });
        }
        return res.json(data);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.put('/api/tasks/:id', verifyToken, async (req, res) => {
    try {
        const { id: taskId } = req.params;
        const { title, description, completed } = req.body;
        const { id: userId } = req.user;
        const { data, error } = await supabase.from('task_manager_tasks').update({ id: taskId, title, description, completed }).eq('id', taskId).eq('user_id', userId);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        return res.json(data[0]);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.delete('/api/tasks/:id', verifyToken, async (req, res) => {
    try {
        const { id: taskId } = req.params;
        const { id: userId } = req.user;
        const { data, error } = await supabase.from('task_manager_tasks').delete().eq('id', taskId).eq('user_id', userId);
        if (error || !data || data.length === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        return res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server started on port ${port}`));