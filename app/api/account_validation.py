"""Provided error redaction scoped to the NEW account routers only."""
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute


class SensitiveRoute(APIRoute):
    def get_route_handler(self):
        original_handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                return await original_handler(request)
            except RequestValidationError:
                # No input, ctx, dynamic field name, body or parser excerpt.
                return JSONResponse(status_code=422, content={"detail": [
                    {"type": "invalid_request", "loc": ["request"],
                     "msg": "invalid input"}
                ]})

        return safe_handler
