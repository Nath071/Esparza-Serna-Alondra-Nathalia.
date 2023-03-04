//Control de flujo

//Cifrado de contraseñas
const bcrypt = require('bcrypt');

//Orden de los elementos array en index
function index(req, res) {
  if (req.session.loggedin) {
    res.redirect('/');
  } else {
    //Redireccionar de login a index
    res.render('login/index');
  }
}
//Orden de los elementos array en register
function register(req, res) {
  if (req.session.loggedin) {
    res.redirect('/');
  } else {
    //Redireccionar de login a register
    res.render('login/register');
  }
  
}
//Funciones del sistema
function storeUser(req,res){
  const data=req.body;
  req.getConnection((err,conn) => {
    //Conexion con la base de datos
    conn.query('SELECT * FROM users WHERE email= ?',[data.email], (err,userData) => {
      if (userData.length>0){
        //Redireccionar si el usuario ya existe
        res.render('login/register', {error: 'User already exists'});
      } else {
        //Hashing de passwords
        bcrypt.hash(data.password, 12).then(hash => {
          console.log(hash);
          data.password=hash;
          //console.log(data);
          req.getConnection((err,conn) => {
            //Conexion con la base de datos
              conn.query('INSERT INTO users SET ?',[data], (err,rows) => {
                res.redirect('/'); 
              });
          });
      
        });
      }
    });
  });
} 

//Sistema de inicio de sesion
function auth(req, res) {
  const data = req.body;
	//let email = req.body.email;
	//let password = req.body.password;

  //Requisitos del sistema
  req.getConnection((err, conn) => {
    //Conexion con mysql
    conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userData) => {
      if(userData.length > 0) {
        userData.forEach(element => {
          //Hashing de passwords
          bcrypt.compare(data.password,element.password, (err,isMatch) => {
            if(!isMatch){
              console.log("out",userData);
              //Redireccionar si hay error de usuario o contraseña
              res.render('login/index', {error: 'Error password or email do not exist!'});
            } else {
              //Imprimir texto en la consola como mensaje de registro
              console.log("wellcome");
              req.session.loggedin = true;
              req.session.name = element.name;
              res.redirect('/');
            }
          });   
        });     







      } else {
        //Renderizar si hay error en el usuario o contraseña
        res.render('login/index', {error: 'Error password or email do not exist!'});
      }    
    });
  });
}

//Funcion para el logout del usuario
function logout(req, res) {
  if (req.session.loggedin) {
    req.session.destroy();
  }
  res.redirect('/');
}

//Creacion de un modulo en JS
module.exports = {
  index: index,
  register: register,
  auth: auth,
  logout: logout,
  storeUser: storeUser,

}

