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

    // CORRECCIÓN: Usamos path.basename() para eliminar cualquier intento de traversal.
    // Si filename es '../../package.json', basename será 'package.json'.
    const secureFilename = path.basename(filename);

    const logsDir = path.join(__dirname, 'logs');
    const filePath = path.join(logsDir, secureFilename);
    
    // Doble chequeo: Nos aseguramos que la ruta final aún está dentro del directorio de logs.
    if (filePath.indexOf(logsDir) !== 0) {
        return res.status(400).send('Intento de acceso a archivo no válido.');
    }

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            // Se devuelve un error genérico para no filtrar si un archivo existe o no.
            return res.status(404).send('Archivo no encontrado o no se pudo leer.');
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