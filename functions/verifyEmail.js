const axios = require('axios');
const qs = require('qs');

const User = require('../schema/userSchema');

function verifyEmail(data) {
    User.where({username: data.email}).findOne((err, user) => {
        if(err)
        {
            console.log(0,JSON.stringify(err))
            return 0;
        }
        else if(user)
        {
            if(user.mailTrack.length == 5 && (user.mailTrack[0]+(24*60*60*1000))> (new Date().getTime()))
            {
                return 3;
            }
            // eslint-disable-next-line no-undef
            axios.post(process.env.VERIFY_URL, qs.stringify(data))
            .then(response => {
                
                if(response.data.status === 1)
                {
                    if(user.mailTrack.length===5)
                    {
                        user.mailTrack.shift();
                    }
                    user.mailTrack.push(new Date().getTime());
                    user.save();

                    return 1;
                }
                else
                {
                    console.log(4,'Mail send error',JSON.stringify(response))
                    return 4;
                }
            })
            .catch(error => {
                console.log(5,JSON.stringify(error))
                return 5;
            })
        }
        else
        {
            return 2;
        }
    })
}

module.exports = verifyEmail;