#!/usr/bin/env python

from flask import request, session,jsonify,make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()
        
        required_fields = ['username', 'password', 'image_url', 'bio']
        for field in required_fields:
            if field not in json_data:
                return {'error': f'Missing field: {field}'}, 422
        
        if User.query.filter_by(username=json_data['username']).first():
            return {'error': 'Username already exists'}, 422
        
        user = User(
            username=json_data['username'],
            image_url=json_data['image_url'],
            bio=json_data['bio']
        )
        
        user.password_hash = json_data['password']
        
        db.session.add(user)
        db.session.commit()
        
        response_data = {
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }
        return response_data, 201
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id is not None:
            user = User.query.filter(User.id == user_id).first()
            if user is not None:
                return user.to_dict(),200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):

    def post(self):
        data = request.get_json()
        username = data['username']
        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            response_data = {
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }
            return response_data, 200

        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id is not None:
            session.pop('user_id',None)
            return {}, 204
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            recipes = Recipe.query.all()
            return [{
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            } for recipe in recipes], 200
        return {"error": "Unauthorized"}, 401

    def post(self):
        user_id = session.get('user_id')
        if user_id:
            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            if not title:
                return {"error": "Title is required."}, 422

            if not instructions or len(instructions) < 50:
                return {"error": "Instructions are required and must be at least 50 characters long."}, 422

            if not minutes_to_complete:
                return {"error": "Minutes to complete is required."}, 422

            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()

            return {
                "id": new_recipe.id,
                "title": new_recipe.title,
                "instructions": new_recipe.instructions,
                "minutes_to_complete": new_recipe.minutes_to_complete,
                "user": {
                    "id": new_recipe.user.id,
                    "username": new_recipe.user.username,
                    "image_url": new_recipe.user.image_url,
                    "bio": new_recipe.user.bio
                }
            }, 201
        return {"error": "Unauthorized"}, 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)