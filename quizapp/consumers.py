from channels.generic.websocket import AsyncJsonWebsocketConsumer

class RealtimeConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        user = self.scope["user"]

        if not user.is_authenticated:
            await self.close()
            return

        await self.channel_layer.group_add("realtime_updates", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("realtime_updates", self.channel_name)

    async def send_update(self, event):
        await self.send_json(event["data"])
