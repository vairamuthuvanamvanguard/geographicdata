from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .mongodb_utils import get_mongo_database
import bcrypt  # You should hash passwords before storing them

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
                # The password is correct
                return JsonResponse({'message': 'Login successful'})
            else:
                return JsonResponse({'message': 'Invalid credentials'}, status=401)
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

