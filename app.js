if(process.env.NODE_ENV!=='production')
{
  require('dotenv').config()
}
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require('mongoose');
const app = express();
const _ = require('lodash');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const flash = require('connect-flash');
const mongoSanitize = require('express-mongo-sanitize')
const catchAsync = require('./catchasync')
const ExpressError = require('./error')
const MongoStore=require('connect-mongo').default
const dbUrl =process.env.DB_URL || 'mongodb://localhost:27017/todo';
// ||'mongodb://localhost:27017/todo';
mongoose.connect(dbUrl, { useCreateIndex: true, useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false })

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const secret=process.env.SECRET || 'Thisisoursecret.';
const store=new MongoStore({
  mongoUrl:dbUrl,
  secret,
  touchAfter:24*60*60,

})
store.on('err',function(e){
  console.log("Session Errr:",e)
})
const sessionConfig={
  store,
   name:'sessions',
   secret,
   resave:false,
   saveUninitialized:true,
   cookie:{
       httpOnly:true,
          expires:Date.now()+1000*60*60*24*7,
          maxAge:1000*60*60*24*7
      }
}
app.use(session(sessionConfig));
app.use(flash());

app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
})
app.use(mongoSanitize({
  replaceWith: '_'
}));
const userSchema = new mongoose.Schema({
  username: {
    type: String,
  },
  lists: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'List'
  }]
});
userSchema.plugin(passportLocalMongoose);
const User = new mongoose.model('User', userSchema);
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

const itemsSchema = new mongoose.Schema({
  name: String
});
const listSchema = new mongoose.Schema({
  name: 'String',
  items: [itemsSchema],


});


const Item = mongoose.model('Item', itemsSchema);
const List = mongoose.model('List', listSchema);
const item1 = new Item({ name: "Welcome to your TODO list!" });
const item2 = new Item({ name: "Hit the '+' button to add a new item." });
const item3 = new Item({ name: "<-- Hit this to delete an item." });
app.get('/', (req, res) => {
  res.render('home');
})
app.get('/login', (req, res) => {
  res.render('login');
})
app.get('/register', (req, res) => {
  res.render('register');
})
app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
})

app.post('/register', async (req, res, next) => {
  try {
    User.register({ username: req.body.username }, req.body.password,
      (err, user) => {
        if (err) {
          req.flash('error', err.message);
          res.redirect('/register')
        }
        else {
          passport.authenticate("local")(req, res, () => {
            req.flash('success', 'Welcome to My ToDo!');
            res.redirect('/');
          })
        }
      })
  } catch (e) {
    req.flash('error', e.message);
    res.redirect('/register')
  }

})
app.get('/userhome', catchAsync(async (req, res) => {
  if (req.isAuthenticated()) {
    const userlist = await User.findOne({ _id: req.user._id }).populate('lists');
res.render('link', { lists: userlist.lists })
  } else res.redirect('/login')

}))
app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  })

  req.login(user, (err) => {
    if (err) {
      req.flash('error', err.message);
      res.redirect('/login')
    }
    else {
      passport.authenticate("local", { failureFlash: true, failureRedirect: '/login' })(req, res, () => {
        req.flash('success', 'Welcome Back!!');
          res.redirect('/');
      })
    }
  })

})
app.post("/", catchAsync(async function (req, res) {
  if (!req.body.newItem) throw new ExpressError("List Item Cant be empty!!", 400)
  const item = new Item({ name: req.body.newItem });
  const list = req.body.list;
  if (list === 'Today') {
    item.save();
    res.redirect("/gettodo");
  }
  else {
    List.findOne({ name: list }, (err, result) => {
      if (!err) {
        result.items.push(item);
        result.save();
        res.redirect('/' + list);
      }
    })
  }
}));
app.post("/delete", catchAsync(async function (req, res) {
  const listname = req.body.listname;
  if (listname === 'Today') {
    await Item.deleteOne({ _id: req.body.checkbox });
    res.redirect("/gettodo");
  }
  else {
    List.findOneAndUpdate({ name: listname }, { $pull: { items: { _id: req.body.checkbox } } }, (err, result) => {
      if (!err) {
        req.flash('success', "Successfully Deleted list Item!")
        res.redirect('/' + listname);
      }
    })
  }
}));

app.get("/:list", catchAsync(async function (req, res, next) {

  if (req.user) {
    if (!req.params.list) throw new ExpressError("ToDo name cant be blank!!", 400)
    const y = _.capitalize(req.params.list);
    const lists1 = await User.findOne({ _id: req.user._id }).populate('lists');
    User.findOne({ _id: req.user._id }, (err, user) => {
      const i = lists1.lists.find(k => k.name === y);
    
      if (!i) {
        return next(new ExpressError("Page not Found!!!", 404));
      }
      res.render('list', { listTitle: y, newListItems: i.items, id: i._id, lists: lists1.lists })
    })
  }
  else
    res.render('login')

}))
app.post('/new', catchAsync(async (req, res) => {
  if (req.user) {
 const y = _.capitalize(req.body.search);
    const lists1 = await User.findOne({ _id: req.user._id }).populate('lists');
    User.findOne({ _id: req.user._id }, (err, user) => {
      const i = lists1.lists.find(k => k.name === y);
      if (!i) {
        const list = new List({
          name: y,
          items: [item1, item2, item3],
        });
        list.save();
        user.lists.push(list._id);
        user.save();
    req.flash('success', 'Successfully Created list!');

        res.redirect('/' + y);
      }
      else {
        req.flash('error', 'List already exists, try creating one with another name!!')
        res.redirect('/' + y);
      }
    })
  }
  else
    res.redirect('/login')
}))

app.post('/del-list', catchAsync(async (req, res, next) => {
  if (req.isAuthenticated()) {
    const id = req.body.dellist;
    const user = await User.findByIdAndUpdate(req.user._id, { $pull: { lists: id } });
    const y = await List.findByIdAndRemove(id);
    req.flash('success', 'Successfully deleted list!');
    res.redirect('/userhome');
  }
  else req.redirect('/login');
}))
app.all('*', (req, res, next) => {
  next(new ExpressError("Page not Found!!!", 404))
})
app.use((err, req, res, next) => {
  const { statusCode = 500 } = err;
  if (!err.message) err.message = "Something went Wrong!!!";
  res.status(statusCode);
  res.render('error', { err });
})
const port=process.env.PORT||3000;
app.listen(port, function () {
  console.log("Server started on port: " + port);
});
