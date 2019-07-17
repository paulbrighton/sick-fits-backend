const { forwardTo } = require('prisma-binding')
const { hasPermission } = require('../utils')

const Query = {
  items: forwardTo('db'),
  item: forwardTo('db'),
  itemsConnection: forwardTo('db'),
  me (parent, args, ctx, info) {
    if (!ctx.request.userId) {
      return null
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId }
      }, info
    )
  },
  async users (parent, args, ctx, info) {
    // 1. Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!')
    }
    console.log(ctx.request.userId)
    // 2. Check if the user has the permissions to query all the users
    hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE'])

    // 2. if they do, query all the users!
    return ctx.db.query.users({}, info)
  },
  async order (parent, args, ctx, info) {
    // check they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do this!')
    }
    // query current order
    const order = await ctx.db.query.order({
      where: {
        id: args.id
      }
    }, info)
    // check if the user has permission to see order
    // hasPermission(ctx.request.user, ['ADMIN', 'USER'])
    const ownsOrder = order.user.id === ctx.request.userId
    const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN', 'USER')
    if (!ownsOrder || !hasPermissionToSeeOrder) {
      throw new Error('You don\'t have permission to see this order!')
    }
    return order
  },
  async orders (parent, args, ctx, info) {
    const { userId } = ctx.request
    if (!userId) {
      throw new Error('You must be logged in to see this page')
    }
    return ctx.db.query.orders({
      where: {
        user: { id: userId }
      }
    }, info)
  }
}

module.exports = Query
