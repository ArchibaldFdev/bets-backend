const Koa = require('koa'); // ядро
const Router = require('koa-router'); // маршрутизация
const bodyParser = require('koa-bodyparser'); // парсер для POST запросов
const serve = require('koa-static'); // модуль, который отдает статические файлы типа index.html из заданной директории
const logger = require('koa-logger'); // опциональный модуль для логов сетевых запросов. Полезен при разработке.

const passport = require('koa-passport'); //реализация passport для Koa
const LocalStrategy = require('passport-local'); //локальная стратегия авторизации
const JwtStrategy = require('passport-jwt').Strategy; // авторизация через JWT
const ExtractJwt = require('passport-jwt').ExtractJwt; // авторизация через JWT

const jwtsecret = "mysecretkey"; // ключ для подписи JWT
const jwt = require('jsonwebtoken'); // аутентификация  по JWT для hhtp
const socketioJwt = require('socketio-jwt'); // аутентификация  по JWT для socket.io
const cors = require('@koa/cors');


const socketIO = require('socket.io');

const mongoose = require('mongoose'); // стандартная прослойка для работы с MongoDB
const crypto = require('crypto'); // модуль node.js для выполнения различных шифровальных операций, в т.ч. для создания хэшей.

const app = new Koa();
const router = new Router();
app.use(serve('public'));
app.use(logger());
app.use(bodyParser());
app.use(cors());

app.use(passport.initialize()); // сначала passport
app.use(router.routes()); // потом маршруты
const server = app.listen(3112);// запускаем сервер на порту 3112

mongoose.Promise = Promise; // Просим Mongoose использовать стандартные Промисы
mongoose.set('debug', true);  // Просим Mongoose писать все запросы к базе в консоль. Удобно для отладки кода
mongoose.connect('mongodb://localhost/bets'); // Подключаемся к базе test на локальной машине. Если базы нет, она будет создана автоматически.
mongoose.connection.on('error', console.error);
mongoose.connection.on('connected', function() {
  createAdminUser();
});

//---------Схема и модель пользователя------------------//

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  fathersName : String,
  phone : String,
  email: {
    type: String,
    required: 'Укажите e-mail',
    unique: 'Такой e-mail уже существует'
  },
  balanceFree : { type: Number, default: 0},
  balanceGame : { type: Number, default: 0},
  passwordHash: String,
  status : String,
  comments : String,
  role : String,
  salt: String,
}, {
  timestamps: true
});

const matchSchema = new mongoose.Schema({
  sport: String,
  country: String,
  league : String,
  team_1 : String,
  team_2 : String,
  date : String,
  time: String,
  bets : {},
}, {
  timestamps: true
});

const betSchema = new mongoose.Schema({
  userId: String,
  user : {},
  match: {},
  betValue : Number,
  betType : String,
  status : {'type' : String, default: 'active'},
  comment : {'type' : String, default: 'Its allright!'}
  }, {
  timestamps: true
});

const depositSchema = new mongoose.Schema({
  userId: String,
  user : {},
  depositValue : Number,
  paymentType : String,
  phone : String,
  status : {'type' : String, default: 'pending'},
  comment : {'type' : String, default: 'Its allright!'}
}, {
  timestamps: true
});

userSchema.virtual('password')
.set(function (password) {
  console.log('MONGO VIRT METHOD  PASSWORD=,',password);
  this._plainPassword = password;
  if (password) {
    this.salt = crypto.randomBytes(128).toString('base64');
    this.passwordHash = crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha1');
  } else {
    this.salt = undefined;
    this.passwordHash = undefined;
  }
})

.get(function () {
  return this._plainPassword;
});

userSchema.methods.checkPassword = function (password) {
  if (!password) return false;
  if (!this.passwordHash) return false;
  return crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha1') == this.passwordHash;
};

const User = mongoose.model('User', userSchema);
const Match = mongoose.model('Match', matchSchema);
const Bet = mongoose.model('Bet', betSchema);
const Deposit = mongoose.model('Deposit', depositSchema);

//----------Passport Local Strategy--------------//

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    session: false
  },
  function (email, password, done) {
    User.findOne({email}, (err, user) => {
      if (err) {
        return done(err);
      }
      
      if (!user || !user.checkPassword(password)) {
        return done(null, false, {message: 'Нет такого пользователя или пароль неверен.'});
      }
      return done(null, user);
    });
  }
  )
);

//----------Passport JWT Strategy--------//

// Ждем JWT в Header

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeader(),
  secretOrKey: jwtsecret
};

passport.use(new JwtStrategy(jwtOptions, function (payload, done) {
    User.findById(payload.id, (err, user) => {
      if (err) {
        return done(err)
      }
      if (user) {
        done(null, user)
      } else {
        done(null, false)
      }
    })
  })
);

//------------Routing---------------//

//маршрут для создания нового пользователя

router.post('/user', async(ctx, next) => {
  try {
    ctx.body = await User.create(ctx.request.body);
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.post('/match', async(ctx, next) => {
  try {
    if(ctx.request.body.type === 'update') {
      await Match.remove();
    }
    ctx.body = await Match.insertMany(ctx.request.body.matches);
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.get('/match', async(ctx, next) => {
  try {
    const matches = await Match.find({});
    ctx.body = parseData(matches);
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.get('/bets', async(ctx, next) => {
  try {
    const bets = await Bet.find({});
    ctx.body = bets;
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.get('/bets/:userId', async(ctx, next) => {
  try {
    const bets = await Bet.find({"userId" : ctx.params.userId});
    ctx.body = bets;
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.put('/user/:userId', async(ctx, next) => {
  try {
    let user = await User.findOne({"_id" : ctx.params.userId});
    if(ctx.request.body.password) {
      if(user.checkPassword(ctx.request.body.oldPassword)) {
        user.password = ctx.request.body.password;
        await user.save();
        ctx.body = user;
      }
      else {
        ctx.status = 400;
        ctx.body = 'Текущий пароль введен неверно!Повторите ввод.';
      }
    }
    else {
      user = await User.findOneAndUpdate({"_id": ctx.params.userId}, {"$set" : {"email" :ctx.request.body.email}});
      ctx.body = {newEmail : user.email};
    }
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.post('/deposit/:userId', async(ctx, next) => {
  try {
    const user = await User.findOne({"_id" : ctx.params.userId});
    if(user) {
      let createDepositData = ctx.request.body;
      createDepositData.user = user;
      const deposit = await Deposit.create(createDepositData);
      if(deposit) {
        user.balanceFree = Number(ctx.request.body.depositValue) + user.balanceFree;
        await user.save();
        ctx.body = {balanceFree : user.balanceFree};
      }
    }
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

router.get('/deposit', async(ctx, next) => {
  try {
    const deposits = await Deposit.find({});
    ctx.body = deposits;
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});



// router.get('/match', async(ctx, next) => {
//   await passport.authenticate('jwt', async(err, user) => {
//     if (user) {
//       try {
//         const matches = await Match.find({});
//         ctx.body = parseData(matches);
//       }
//       catch (err) {
//         ctx.status = 400;
//         ctx.body = err;
//       }
//     } else {
//       ctx.body = "No such user";
//       console.log("err", err)
//     }
//   })(ctx, next)
// });



//маршрут для локальной авторизации и создания JWT при успешной авторизации

router.post('/login', async(ctx, next) => {
  await passport.authenticate('local', function (err, user) {
    if (user == false) {
      ctx.body = "Login failed";
    } else {
      //--payload - информация которую мы храним в токене и можем из него получать
      const payload = {
        id: user.id,
        login: user.login,
        email: user.email
      };
      const token = jwt.sign(payload, jwtsecret); //здесь создается JWT
      user.token = 'JWT ' + token;
      const userData = {
        userId : user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        fathersName : user.fathersName,
        phone : user.phone,
        email: user.email,
        balanceFree : user.balanceFree,
        balanceGame : user.balanceGame,
        role : user.role,
        token : 'JWT ' + token
      };
      ctx.body = {user : userData};
    }
  })(ctx, next);
  
});

// маршрут для авторизации по токену

router.get('/custom', async(ctx, next) => {

  await passport.authenticate('jwt', function (err, user) {
    if (user) {
      ctx.body = "hello " + user.displayName;
    } else {
      ctx.body = "No such user";
      console.log("err", err)
    }
  } )(ctx, next)
  
});

router.post('/yandex', async(ctx, next) => {
  console.log('Yandex Responce=',ctx);
});

router.post('/bet', async(ctx, next) => {
  try {
    const user = await User.findOne({"_id" :ctx.request.body.userId});
    if(user) {
      let createBetData = ctx.request.body;
      createBetData.user = user;
      const bet = await Bet.create(createBetData);
      if(bet) {
        user.balanceFree = user.balanceFree - Number(ctx.request.body.betValue);
        user.balanceGame = Number(ctx.request.body.betValue) + user.balanceGame;
        await user.save();
        ctx.body = {balanceFree : user.balanceFree, balanceGame : user.balanceGame};
      }
    }
  }
  catch (err) {
    ctx.status = 400;
    ctx.body = err;
  }
});

//---Socket Communication-----//
let io = socketIO(server);

io.on('connection', socketioJwt.authorize({
  secret: jwtsecret,
  timeout: 15000
})).on('authenticated', function (socket) {
  
  console.log('Это мое имя из токена: ' + socket.decoded_token.displayName);
  
  socket.on("clientEvent", (data) => {
    console.log(data);
  })
});

const createAdminUser = async () => {
  try {
    let user = await User.findOne({role: 'admin'});
    if (!user) {
      console.log('ADMIN IS ABSENT!!!');
      console.log('CREATE ADMIN USER!');
      user = {
        firstName: 'Admin',
        lastName: 'Admin',
        fathersName: 'Admin',
        email: 'admin@mail.com',
        password: 'admin',
        role : 'admin'
      };
      let admin = await User.create(user);
      if(admin) {
        console.log('ADMIN IS CREATED!!!');
      }
    }
  }
  catch(err)  {
    console.log('USER NOT CREATED!');
  }
}

const parseData = (data) => {
  let matches = {};
  let elementExist = (dataArray, dataField, value) => {
    return dataArray.some((elem) => elem[dataField] == value)
  };
  matches.sports = [];
  data.forEach((match) => {
    if(!elementExist(matches.sports, 'sport', match.sport)) {
      matches.sports.push({"sport" : match.sport, "countries" : []})
    }
    matches.sports.forEach((sport) => {
      if(sport.sport === match.sport && !elementExist(sport.countries, 'country', match.country)) {
        sport.countries.push({"country" : match.country, "leagues" : []})
      }
      sport.selected = false;
      sport.countries.forEach((country) => {
        if(country.country === match.country && !elementExist(country.leagues, 'league', match.league)) {
          country.leagues.push({"league" : match.league, "matches" : []})
        }
        country.selected = false;
        country.leagues.forEach((league) => {
          league.selected = false;
          if(country.country === match.country && league.league === match.league) {
            league.matches.push(match);
          }
        })
      })
    })
  });

  console.log("PARSED OBJECT=", matches);
  return matches;
}
