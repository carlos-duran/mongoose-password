const bcrypt = require('bcryptjs')

const plugin = (schema, {
  saltWorkFactor = 10,
  passwordPath = 'password',
  methodName = 'comparePassword'
} = {}) => {
  schema.add({
    [passwordPath]: {
      type: String,
      required: true
    }
  })

  schema.pre('save', async function () {
    if (this.isModified('password')) {
      const salt = await bcrypt.genSalt(saltWorkFactor)
      this.password = await bcrypt.hash(this.password, salt)
    }
  })

  schema.methods[methodName] = async function (candidate) {
    return bcrypt.compare(candidate, this.password)
  }
}

module.exports = plugin
