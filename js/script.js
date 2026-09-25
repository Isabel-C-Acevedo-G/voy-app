const API_URL = 'http://localhost:8000';

function mostrarMensaje(elementId, mensaje, tipo) {
    var div = document.getElementById(elementId);
    if (div) {
        div.textContent = mensaje;
        div.className = 'mensaje ' + tipo;
        div.style.display = 'block';
        setTimeout(function() {
            div.style.display = 'none';
        }, 5000);
    }
}

async function peticionAPI(endpoint, method, data, requiereAuth) {
    method = method || 'GET';
    data = data || null;
    requiereAuth = requiereAuth || false;

    var opciones = {
        method: method,
        headers: { 'Content-Type': 'application/json' }
    };

    if (requiereAuth) {
        var token = localStorage.getItem('token');
        if (token) {
            opciones.headers['Authorization'] = 'Bearer ' + token;
        }
    }

    if (data && method !== 'GET') {
        opciones.body = JSON.stringify(data);
    }

    var respuesta = await fetch(API_URL + endpoint, opciones);
    var datos = null;
    try {
        datos = await respuesta.json();
    } catch (e) {
        datos = {};
    }

    if (respuesta.status === 401) {
        if (requiereAuth) {
            // Esto sí llevaba un token: la sesión expiró o ya no es válida.
            cerrarSesion();
            throw new Error('Tu sesión expiró. Inicia sesión nuevamente.');
        }
        // Sin token (ej. el login): un 401 significa credenciales incorrectas,
        // no que haya "expirado" nada.
        throw new Error(datos.detail || 'Usuario o contraseña incorrectos.');
    }

    if (!respuesta.ok) {
        throw new Error(datos.detail || 'Error en la petición');
    }

    return datos;
}

// ---------------------------------------------------------------------------
// Sesión y visibilidad por rol
// ---------------------------------------------------------------------------
function obtenerUsuarioActual() {
    var raw = localStorage.getItem('usuario');
    return raw ? JSON.parse(raw) : null;
}

function actualizarInterfazSegunSesion() {
    var usuario = obtenerUsuarioActual();
    var logueado = !!usuario;

    document.querySelectorAll('.requiere-sesion').forEach(function(el) {
        el.style.display = logueado ? 'block' : 'none';
    });
    document.querySelectorAll('.oculta-con-sesion').forEach(function(el) {
        el.style.display = logueado ? 'none' : 'block';
    });

    document.querySelectorAll('a.requiere-sesion').forEach(function(el) {
        el.style.display = logueado ? 'inline' : 'none';
    });
    document.querySelectorAll('a.oculta-con-sesion').forEach(function(el) {
        el.style.display = logueado ? 'none' : 'inline';
    });

    ['solo-ciclista', 'solo-vigilante', 'solo-admin'].forEach(function(clase) {
        document.querySelectorAll('.' + clase).forEach(function(el) {
            el.style.display = 'none';
        });
    });

    var badge = document.getElementById('badgeSesion');

    if (logueado) {
        badge.style.display = 'inline-block';
        badge.textContent = usuario.nombres + ' · ' + usuario.rol;

        if (usuario.rol === 'Ciclista') {
            document.querySelectorAll('.solo-ciclista').forEach(function(el) { el.style.display = 'block'; });
        } else if (usuario.rol === 'Vigilante') {
            document.querySelectorAll('.solo-vigilante').forEach(function(el) { el.style.display = 'block'; });
        } else if (usuario.rol === 'Administrador') {
            document.querySelectorAll('.solo-vigilante').forEach(function(el) { el.style.display = 'block'; });
            document.querySelectorAll('.solo-admin').forEach(function(el) { el.style.display = 'block'; });
        }
    } else {
        badge.style.display = 'none';
    }
}

function cerrarSesion() {
    localStorage.removeItem('token');
    localStorage.removeItem('usuario');
    actualizarInterfazSegunSesion();
}

// ---------------------------------------------------------------------------
// Modal de Registro: pestañas de rol separadas (Ciclista / Vigilante / Administrador)
// ---------------------------------------------------------------------------
function elegirRolRegistro(rol) {
    document.getElementById('regRol').value = rol;

    var tabs = {
        Ciclista: document.getElementById('tabCiclista'),
        Vigilante: document.getElementById('tabVigilante'),
        Administrador: document.getElementById('tabAdministrador')
    };
    Object.keys(tabs).forEach(function(clave) {
        var boton = tabs[clave];
        if (!boton) return;
        if (clave === rol) {
            boton.className = 'px-4 py-2 rounded-t-lg font-semibold text-sm bg-montana text-white';
        } else {
            boton.className = 'px-4 py-2 rounded-t-lg font-semibold text-sm bg-gray-100 text-gray-500';
        }
    });

    var aviso = document.getElementById('avisoAdmin');
    var campos = document.getElementById('formRegistroCampos');
    if (rol === 'Administrador') {
        aviso.classList.remove('hidden');
        campos.classList.add('hidden');
    } else {
        aviso.classList.add('hidden');
        campos.classList.remove('hidden');
    }
}

// Cierra un modal de Flowbite por su id (usa la API oficial si está cargada).
function cerrarModal(id) {
    try {
        var instancia = window.FlowbiteInstances && window.FlowbiteInstances.getInstance('Modal', id);
        if (instancia) {
            instancia.hide();
            return;
        }
    } catch (e) { /* seguimos con el respaldo de abajo */ }
    var el = document.getElementById(id);
    if (el) el.classList.add('hidden');
}

// ---------------------------------------------------------------------------
// Autenticación
// ---------------------------------------------------------------------------
async function iniciarSesion(usuario, contrasena) {
    try {
        var datos = await peticionAPI('/auth/login', 'POST', { usuario: usuario, contrasena: contrasena });
        if (datos.access_token) {
            localStorage.setItem('token', datos.access_token);
            localStorage.setItem('usuario', JSON.stringify(datos.usuario));
            mostrarMensaje('msgLogin', 'Bienvenido ' + datos.usuario.nombres, 'exito');
            actualizarInterfazSegunSesion();
            setTimeout(function() { cerrarModal('modalLogin'); }, 900);
        }
    } catch (error) {
        mostrarMensaje('msgLogin', error.message, 'error');
    }
}

async function registrarUsuario(datosUsuario) {
    try {
        await peticionAPI('/auth/register', 'POST', datosUsuario);
        mostrarMensaje('msgRegistro', 'Usuario registrado correctamente. Ahora puedes iniciar sesión.', 'exito');
        ['regDocumento', 'regNombres', 'regApellidos', 'regCorreo', 'regTelefono', 'regContrasena'].forEach(function(id) {
            document.getElementById(id).value = '';
        });
        setTimeout(function() {
            cerrarModal('modalRegistro');
            var botonLogin = document.querySelector('[data-modal-target="modalLogin"]');
            if (botonLogin) botonLogin.click();
        }, 1200);
    } catch (error) {
        mostrarMensaje('msgRegistro', error.message, 'error');
    }
}

// ---------------------------------------------------------------------------
// Disponibilidad (pública)
// ---------------------------------------------------------------------------
async function consultarDisponibilidad() {
    try {
        var datos = await peticionAPI('/disponibilidad', 'GET');
        var div = document.getElementById('resultadoDisponibilidad');
        if (div && datos.datos) {
            div.innerHTML = '<strong>Disponibilidad Actual:</strong><br>' +
                'Cupos Libres: ' + datos.datos.cupos_libres + '<br>' +
                'Cupos Ocupados: ' + datos.datos.cupos_ocupados + '<br>' +
                'Cupos Reservados: ' + datos.datos.cupos_reservados + '<br>' +
                '<strong>Total: ' + datos.datos.total_cupos + '</strong>';
            div.className = 'mensaje exito';
            div.style.display = 'block';
        }
    } catch (error) {
        mostrarMensaje('resultadoDisponibilidad', 'Error al consultar disponibilidad', 'error');
    }
}

// ---------------------------------------------------------------------------
// Bicicletas (Ciclista)
// ---------------------------------------------------------------------------
async function registrarBicicleta(marca, modelo, color, numeroSerie) {
    try {
        await peticionAPI('/bicicletas/registrar', 'POST', {
            marca: marca || null, modelo: modelo || null, color: color || null, numero_serie: numeroSerie
        }, true);
        mostrarMensaje('msgBici', 'Bicicleta registrada correctamente.', 'exito');
        document.getElementById('biciMarca').value = '';
        document.getElementById('biciModelo').value = '';
        document.getElementById('biciColor').value = '';
        document.getElementById('biciSerie').value = '';
        setTimeout(function() { cerrarModal('modalBici'); }, 1200);
    } catch (error) {
        mostrarMensaje('msgBici', error.message, 'error');
    }
}

// ---------------------------------------------------------------------------
// Reservas (Ciclista)
// ---------------------------------------------------------------------------
async function crearReserva(numeroSerie) {
    try {
        var datos = await peticionAPI('/reservas/crear', 'POST', { numero_serie_bici: numeroSerie }, true);
        mostrarMensaje('msgReserva', 'Reserva creada. Expira a las ' + datos.datos.fecha_expiracion, 'exito');
    } catch (error) {
        mostrarMensaje('msgReserva', error.message, 'error');
    }
}

// ---------------------------------------------------------------------------
// Ingresos / Salidas (Vigilante, Administrador)
// ---------------------------------------------------------------------------
async function registrarIngreso(documento, serie) {
    try {
        await peticionAPI('/ingresos/registrar', 'POST', {
            documento_usuario: documento,
            numero_serie_bici: serie || null
        }, true);
        mostrarMensaje('msgIngreso', 'Ingreso registrado exitosamente. Espacio asignado.', 'exito');
        setTimeout(function() { cerrarModal('modalIngreso'); }, 1200);
    } catch (error) {
        mostrarMensaje('msgIngreso', error.message, 'error');
    }
}

async function registrarSalida(documento) {
    try {
        await peticionAPI('/salidas/registrar', 'POST', { documento_usuario: documento }, true);
        mostrarMensaje('msgSalida', 'Salida registrada exitosamente', 'exito');
        setTimeout(function() { cerrarModal('modalSalida'); }, 1200);
    } catch (error) {
        mostrarMensaje('msgSalida', error.message, 'error');
    }
}

// ---------------------------------------------------------------------------
// Incidentes (Vigilante, Administrador)
// ---------------------------------------------------------------------------
async function registrarIncidente(tipo, idUsuario, idBicicleta, descripcion) {
    try {
        await peticionAPI('/incidentes/registrar', 'POST', {
            tipo_incidente: tipo,
            id_usuario: idUsuario ? parseInt(idUsuario, 10) : null,
            id_bicicleta: idBicicleta ? parseInt(idBicicleta, 10) : null,
            descripcion: descripcion
        }, true);
        mostrarMensaje('msgIncidente', 'Incidente registrado correctamente.', 'exito');
        document.getElementById('incIdUsuario').value = '';
        document.getElementById('incIdBicicleta').value = '';
        document.getElementById('incDescripcion').value = '';
        setTimeout(function() { cerrarModal('modalIncidente'); }, 1200);
    } catch (error) {
        mostrarMensaje('msgIncidente', error.message, 'error');
    }
}

// ---------------------------------------------------------------------------
// Reportes (Administrador)
// ---------------------------------------------------------------------------
async function generarReporte(fechaInicio, fechaFin, tipo) {
    try {
        var datos = await peticionAPI('/reportes/generar', 'POST', {
            fecha_inicio: fechaInicio,
            fecha_fin: fechaFin,
            tipo: tipo
        }, true);
        mostrarMensaje('msgReporte', 'Reporte generado: ' + datos.datos.resumen.total_movimientos +
            ' movimiento(s), ' + datos.datos.resumen.total_incidentes + ' incidente(s).', 'exito');
        pintarTablaReporte(datos.datos.movimientos, datos.datos.incidentes);
    } catch (error) {
        mostrarMensaje('msgReporte', error.message, 'error');
    }
}

function pintarTablaReporte(movimientos, incidentes) {
    var contenedor = document.getElementById('tablaReporte');
    var html = '';

    if (movimientos && movimientos.length) {
        html += '<h4>Movimientos</h4><table><thead><tr>' +
            Object.keys(movimientos[0]).map(function(c) { return '<th>' + c + '</th>'; }).join('') +
            '</tr></thead><tbody>';
        movimientos.forEach(function(fila) {
            html += '<tr>' + Object.values(fila).map(function(v) { return '<td>' + (v ?? '') + '</td>'; }).join('') + '</tr>';
        });
        html += '</tbody></table>';
    }

    if (incidentes && incidentes.length) {
        html += '<h4 style="margin-top:15px;">Incidentes</h4><table><thead><tr>' +
            Object.keys(incidentes[0]).map(function(c) { return '<th>' + c + '</th>'; }).join('') +
            '</tr></thead><tbody>';
        incidentes.forEach(function(fila) {
            html += '<tr>' + Object.values(fila).map(function(v) { return '<td>' + (v ?? '') + '</td>'; }).join('') + '</tr>';
        });
        html += '</tbody></table>';
    }

    contenedor.innerHTML = html || '<p>No hay registros para el período seleccionado.</p>';
}

// ---------------------------------------------------------------------------
// EVENTOS
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    actualizarInterfazSegunSesion();

    var btnLogin = document.getElementById('btnLogin');
    if (btnLogin) {
        btnLogin.addEventListener('click', function(e) {
            e.preventDefault();
            var usuario = document.getElementById('loginUsuario').value;
            var contrasena = document.getElementById('loginContrasena').value;
            if (usuario && contrasena) {
                iniciarSesion(usuario, contrasena);
            } else {
                mostrarMensaje('msgLogin', 'Completa todos los campos', 'error');
            }
        });
    }

    var btnRegistro = document.getElementById('btnRegistro');
    if (btnRegistro) {
        btnRegistro.addEventListener('click', function(e) {
            e.preventDefault();
            var datos = {
                documento: document.getElementById('regDocumento').value,
                nombres: document.getElementById('regNombres').value,
                apellidos: document.getElementById('regApellidos').value,
                correo: document.getElementById('regCorreo').value,
                telefono: document.getElementById('regTelefono').value,
                contrasena: document.getElementById('regContrasena').value,
                rol: document.getElementById('regRol').value
            };
            if (datos.documento && datos.nombres && datos.correo && datos.contrasena) {
                registrarUsuario(datos);
            } else {
                mostrarMensaje('msgRegistro', 'Completa los campos obligatorios (*)', 'error');
            }
        });
    }

    var btnDisp = document.getElementById('btnDisponibilidad');
    if (btnDisp) {
        btnDisp.addEventListener('click', function(e) { e.preventDefault(); consultarDisponibilidad(); });
    }

    var btnBici = document.getElementById('btnRegistrarBici');
    if (btnBici) {
        btnBici.addEventListener('click', function(e) {
            e.preventDefault();
            var serie = document.getElementById('biciSerie').value;
            if (!serie) { mostrarMensaje('msgBici', 'El número de serie es obligatorio', 'error'); return; }
            registrarBicicleta(
                document.getElementById('biciMarca').value,
                document.getElementById('biciModelo').value,
                document.getElementById('biciColor').value,
                serie
            );
        });
    }

    var btnReservar = document.getElementById('btnReservar');
    if (btnReservar) {
        btnReservar.addEventListener('click', function(e) {
            e.preventDefault();
            var serie = document.getElementById('reservaSerie').value;
            if (!serie) { mostrarMensaje('msgReserva', 'Indica el número de serie de tu bicicleta', 'error'); return; }
            crearReserva(serie);
        });
    }

    var btnIng = document.getElementById('btnIngreso');
    if (btnIng) {
        btnIng.addEventListener('click', function(e) {
            e.preventDefault();
            var doc = document.getElementById('ingresoDoc').value;
            var serie = document.getElementById('ingresoSerie').value;
            if (doc) { registrarIngreso(doc, serie); }
            else { mostrarMensaje('msgIngreso', 'Ingresa el documento del ciclista', 'error'); }
        });
    }

    var btnSal = document.getElementById('btnSalida');
    if (btnSal) {
        btnSal.addEventListener('click', function(e) {
            e.preventDefault();
            var doc = document.getElementById('salidaDoc').value;
            if (doc) { registrarSalida(doc); }
            else { mostrarMensaje('msgSalida', 'Ingresa el documento del ciclista', 'error'); }
        });
    }

    var btnInc = document.getElementById('btnIncidente');
    if (btnInc) {
        btnInc.addEventListener('click', function(e) {
            e.preventDefault();
            var descripcion = document.getElementById('incDescripcion').value;
            if (!descripcion || descripcion.length < 10) {
                mostrarMensaje('msgIncidente', 'La descripción debe tener al menos 10 caracteres', 'error');
                return;
            }
            registrarIncidente(
                document.getElementById('incTipo').value,
                document.getElementById('incIdUsuario').value,
                document.getElementById('incIdBicicleta').value,
                descripcion
            );
        });
    }

    var btnRep = document.getElementById('btnReporte');
    if (btnRep) {
        btnRep.addEventListener('click', function(e) {
            e.preventDefault();
            var fi = document.getElementById('repFechaInicio').value;
            var ff = document.getElementById('repFechaFin').value;
            var tipo = document.getElementById('repTipo').value;
            if (!fi || !ff) { mostrarMensaje('msgReporte', 'Selecciona el rango de fechas', 'error'); return; }
            generarReporte(fi, ff, tipo);
        });
    }
});