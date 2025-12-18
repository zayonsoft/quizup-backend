from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


def broadcast_update(payload):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "realtime_updates",
        {
            "type": "send_update",
            "data": payload,
        },
    )


"""
broadcast_update({
    "type": "USER_UPDATED",
    "user_id": user.id,
    "status": user.status,
})

"""
