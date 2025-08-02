const express = require('express');
const { exec } = require('child_process');

const { execFile } = require('child_process');

const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Configurar middleware y motor de plantillas
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- RUTA PRINCIPAL ---
app.get('/', (req, res) => {
    res.render('home');
});

// --- VULNERABILIDAD 1: INYECCIÓN DE COMANDOS ---
app.get('/network', (req, res) => {
    res.render('network', { output: null });
});

app.post('/network/ping', (req, res) => {
    const host = req.body.host;
    // VULNERABILIDAD: El input del usuario se concatena directamente en un comando del sistema.
    // CORRECCIÓN: Usamos execFile para pasar el input como un argumento seguro.
    // El comando 'ping' y sus argumentos ['-c', '1', host] se mantienen separados.
    execFile('ping', ['-c', '1', host], (error, stdout, stderr) => {
        res.render('network', { output: stdout || stderr });
    });
});

// --- VULNERABILIDAD 2: PATH TRAVERSAL ---
app.get('/logs', (req, res) => {
    const filename = req.query.file;
    if (!filename) {
        return res.status(400).send('Por favor, especifique un archivo con el parámetro ?file=');
    }
    // VULNERABILIDAD: El input del usuario se usa para construir una ruta de archivo sin validación.
    const filePath = path.join(__dirname, 'logs', filename);
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.log(err);
            return res.status(500).send('Error al leer el archivo.');
        }
        res.type('text/plain').send(data);
    });
});

// --- VULNERABILIDAD 3: CROSS-SITE SCRIPTING (XSS) REFLEJADO ---
app.get('/search', (req, res) => {
    const searchTerm = req.query.q || '';
    // VULNERABILIDAD: El input se refleja en la plantilla sin ser sanitizado.
    // EJS por defecto escapa (<%= %>), pero usamos <%- %> para hacerlo vulnerable a propósito.
    res.render('search', { searchTerm: searchTerm });
});


app.listen(PORT, () => {
    console.log(`Servidor vulnerable corriendo en http://localhost:${PORT}`);
});