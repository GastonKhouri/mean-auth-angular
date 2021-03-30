const { response } = require('express');
const bcrypt = require('bcryptjs');

const { generarJWT } = require('../helpers/jwt');
const Usuario = require('../models/Usuario');

const crearUsuario = async(req, res = response) => {

	const { email, name, password } = req.body;

	try {

		// Verificar el email
		const usuario = await Usuario.findOne({email});

		if(usuario) {
			return res.status(400).json({
				ok: false,
				msg: 'Ya existe un usuario con ese email'
			})
		}

		// Crear usuario con el modelo
		const dbUser = new Usuario(req.body);

		// Hashear la contraseña
		const salt = bcrypt.genSaltSync();
		dbUser.password = bcrypt.hashSync(password, salt);

		// Generar JWT
		const token = await generarJWT(dbUser.id, name);

		// Crear usuario de DB
		await dbUser.save();

		// Generar respuesta exitosa
		return res.status(201).json({
			ok: true,
			uid: dbUser.id,
			name,
			email,
			token
		});


	} catch(error) {
		console.log(error);
		return res.status(500).json({
				ok: false,
				msg: 'Por favor, hable con el administrador'
			});
	}

}

const loginUsuario = async(req, res) => {

	const { email, password } = req.body; 

	try {

		const dbUser = await Usuario.findOne({email});

		if(!dbUser) {
			return res.status(400).json({
				ok: false,
				msg: 'El correo no existe'
			})
		}

		// Confirmar si password hace match
		const validPassword = bcrypt.compareSync(password, dbUser.password);

		if(!validPassword) {
			return res.status(400).json({
				ok: false,
				msg: 'El password es incorrecto'
			});
		}

		// Generar el JWT
		const token = await generarJWT(dbUser.id, dbUser.name);

		return res.json({
			ok: true,
			uid: dbUser.id,
			name: dbUser.name,
			email: dbUser.email,
			token
		});

	} catch(error) {
		console.log(error);
		return res.status(500).json({
			ok: false,
			msg: 'Por favor, hable con el administrador'
		});
	}

}

const revalidarToken = async(req, res) => {

	const { uid } = req;

	// Leer base de datos
	const dbUser = await Usuario.findById(uid);

	// Generar el JWT
	const token = await generarJWT(uid, dbUser.name);

	return res.json({
		ok: true,
		uid,
		name: dbUser.name,
		email: dbUser.email,
		token
	});
	
}


module.exports = {
	crearUsuario,
	loginUsuario,
	revalidarToken
}