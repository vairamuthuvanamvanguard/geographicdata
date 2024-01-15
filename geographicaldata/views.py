from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .mongodb_utils import get_mongo_database
import bcrypt  # You should hash passwords before storing them
from .models import Shapefile
from .script import read_shapefile
import jwt
from django.conf import settings
from datetime import datetime, timedelta

@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            db = get_mongo_database()
            users = db.users

            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password'].encode('utf-8')

            # Hash the password
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

            if users.find_one({'username': username}):
                return JsonResponse({'error': 'Username already exists'}, status=400)
            if users.find_one({'email': email}):
                return JsonResponse({'error': 'Email already exists'}, status=400)

            users.insert_one({'username': username, 'email': email, 'password': hashed_password})
            return JsonResponse({'message': 'User created successfully'})
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            db = get_mongo_database()
            users = db.users

            email = request.POST['email']
            password = request.POST['password'].encode('utf-8')

            user = users.find_one({'email': email})
            if user and bcrypt.checkpw(password, user['password']):
                # Create token
                payload = {
                    'user_id': str(user['_id']),  # Unique identifier for the user
                    'exp': datetime.utcnow() + timedelta(days=1)  # Expiration time
                }
                token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

                return JsonResponse({'message': 'Login successful', 'token': token})
            else:
                return JsonResponse({'message': 'Invalid credentials'}, status=401)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


@csrf_exempt
def upload_shapefile(request):
    if request.method == 'POST':
        try:
            # Extract the token from the request headers
            token = request.headers.get('Authorization').split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload['user_id']
            # Fetch user based on user_id, ensure user exists
            shapefile = request.FILES['file']
            # Proceed with saving the file associated with the user
            return JsonResponse({'message': 'File uploaded successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


def user_shapefiles(request):
    if request.method == 'GET':
        try:
            user_shapefiles = Shapefile.objects.filter(user=request.user)

            shapefiles_data = []
            for sf in user_shapefiles:
                file_path = sf.file.path
                shapefile_data = read_shapefile(file_path)  # Use the function from step 1
                shapefiles_data.append({
                    'id': sf.id,
                    'file_url': sf.file.url,
                    'uploaded_at': sf.uploaded_at,
                    'data': shapefile_data  # JSON representation of shapefile data
                })

            return JsonResponse({'shapefiles': shapefiles_data}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)
