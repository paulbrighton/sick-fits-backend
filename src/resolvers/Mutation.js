const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { randomBytes } = require('crypto')
const { promisify } = require('util')
const { transport, makeANiceEmail } = require('../mail')
const { hasPermission } = require('../utils')
const stripe = require('../stripe')

const Mutations = {
  async createItem (parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!')
    }
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          user: {
            connect: {
              id: ctx.request.userId
            }
          },
          ...args
        }
      },
      info
    )

    return item
  },
  updateItem (parent, args, ctx, info) {
    // fist take a copy of updates
    const updates = { ...args }
    // remove the ID from updates
    delete updates.id
    // run the update method
    return ctx.db.mutation.updateItem({
      data: updates,
      where: {
        id: args.id
      }
    },
    info
    )
  },
  async deleteItem (parent, args, ctx, info) {
    const where = { id: args.id }
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title user{ id } }`)
    // 2. Check if they own that item, or have the permissions
    const ownsItem = item.user.id === ctx.request.userId
    const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'DELETEITEM'].includes(permission))

    if (!ownsItem && !hasPermissions) {
      throw new Error('You don\'t have the permission to do that!!!')
    }
    // 3. Delete it!
    return ctx.db.mutation.deleteItem({ where }, info)
  },
  async signUp (parent, args, ctx, info) {
    args.email = args.email.toLowerCase()
    // Hash users password (encription)
    const password = await bcrypt.hash(args.password, 10)
    const user = await ctx.db.mutation.createUser({
      data: {
        ...args,
        password,
        permissions: { set: ['USER'] }
      }
    },
    info
    )
    // Create JWT token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET)
    // Set jwt token as a cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      // 1 year cookie
      maxAge: 1000 * 60 * 60 * 24 * 365
    })
    return user
  },
  async signin (parent, {email, password}, ctx, info) {
  // Check if there is a user with that email
    const user = await ctx.db.query.user({where: { email }})
    if (!user) {
      throw new Error(`No such user found for email ${email}`)
    }
    // Check if the password is correct
    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      throw new Error('Invalid password!')
    }
    // Generate a jwt token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET)
    // set cookie with token
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 360
    })
    // return user
    return user
  },
  signout (parent, args, ctx, info) {
    ctx.response.clearCookie('token')
    return { message: 'Goodbye! Thanks for shopping with us.' }
  },
  async requestReset (parent, args, ctx, info) {
    // Check if it is a real user
    const user = await ctx.db.query.user({where: { email: args.email }})
    if (!user) {
      throw new Error(`No such user found for email ${args.email}`)
    }
    // Set reset token and expiry on that user
    const randomBytesPromisified = promisify(randomBytes)
    const resetToken = (await randomBytesPromisified(20)).toString('hex')
    const resetTokenExpiry = Date.now() + 3600000 // 1 hour
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    })
    // email user reset token
    const mailRes = await transport.sendMail({
      from: 'brighton.paul@yahoo.com',
      to: user.email,
      subject: 'Your Password Reset Token',
      html: makeANiceEmail(`Your Password Reset Token is here!
      <br>
      <a href=${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}>Click Here to Reset</a>`)
    })
    // Return the message
    return {message: 'Thanks!'}
  },
  async resetPassword (parent, args, ctx, info) {
    // check if passwords match
    if (args.password !== args.confirmPassword) {
      throw new Error("Passwords don't match, please try again.")
    }
    // check if its a legit reset token
    // check if its expried
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    })
    if (!user) {
      throw new Error('This token is either invalid or expired')
    }
    // hash the new password
    const password = await bcrypt.hash(args.password, 10)
    // save new password and remove old reset token
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null

      }
    })
    // generate jwt token
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET)
    // set jwt cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 360
    })
    // return updated user
    return updatedUser
  },
  async updatePermissions (parent, args, ctx, info) {
    // check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in')
    }
    // query the current user
    const currentUser = await ctx.db.query.user(
      {
        where: {
          id: ctx.request.userId
        }
      },
      info
    )
    // check if they have correct permissions
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE'])
    // update permissions
    return ctx.db.mutation.updateUser({
      data: {
        permissions: {
          set: args.permissions
        }
      },
      where: {
        id: args.userId
      }
    }, info)
  },
  async addToCart (parent, args, ctx, info) {
    // make sure they are signed in
    const { userId } = ctx.request
    if (!userId) {
      throw new Error('You must be signed in soooon')
    }
    // check the users current cart
    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id }
      }
    })
    // check if an item is already in cart and increment by 1 if it is
    if (existingCartItem) {
      console.log('This item is already in their cart')
      return ctx.db.mutation.updateCartItem(
        {
          where: { id: existingCartItem.id },
          data: { quantity: existingCartItem.quantity + 1 }
        },
        info
      )
    }
    // 4. if it's not, create a new CartItem
    return ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: { id: userId }
          },
          item: {
            connect: { id: args.id }
          }
        }
      },
      info
    )
  },
  async removeFromCart (parent, args, ctx, info) {
    // find cart item
    const cartItem = await ctx.db.query.cartItem(
      {
        where: {
          id: args.id
        }
      },
      `{id, user { id }}`
    )
    // make sure there is an item
    if (!cartItem) throw new Error('No cart item found!')
    // check user owns item
    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error('You cheating person!!!')
    }
    // delete cart item
    return ctx.db.mutation.deleteCartItem({
      where: {
        id: args.id
      }
    }, info)
  },
  async createOrder (parent, args, ctx, info) {
    // query current user and check they are signed in
    const { userId } = ctx.request
    if (!userId) throw new Error('You must be logged in to complete your order!')
    const user = await ctx.db.query.user(
      { where: { id: userId } },
      `{
        id 
        name 
        cart { 
          id 
          quantity 
          item {
            title 
            price 
            id 
            description 
            image
            largeImage
          }
        }
      }`
    )
    // recalculate total for price
    const amount = user.cart.reduce((tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    )
    console.log(`Going to charge user for the amount of ${amount}!`)
    // create stripe charge(turn token into money)
    const charge = await stripe.charges.create({
      amount: amount,
      currency: 'GBP',
      source: args.token
    })
    // convert cart items to order items
    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: { connect: { id: userId } }
      }
      delete orderItem.id
      return orderItem
    })
    // create order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        items: { create: orderItems },
        user: { connect: { id: userId } }
      }
    })
    // clear the users cart
    const cartItemIds = user.cart.map(cartItem => cartItem.id)
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds
      }
    })
    // return order to user
    return order
  }
}

module.exports = Mutations
