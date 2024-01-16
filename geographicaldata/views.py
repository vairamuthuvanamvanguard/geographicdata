from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .mongodb_utils import get_mongo_database
import bcrypt  # You should hash passwords before storing them
from .models import Shapefile, MyUser
from .script import read_shapefile
import jwt
from django.conf import settings
from datetime import datetime, timedelta
from gridfs import GridFS
import io
from bson import ObjectId
from django.http import HttpResponse

@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            db = get_mongo_database()
            users = db.users
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password'].encode('utf-8')
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
            username = request.POST['username']
            password = request.POST['password']
            db = get_mongo_database()
            users = db.users
            user = users.find_one({'username': username})
            # Check if user exists and password is correct
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                # Correctly access _id from the user dictionary
                encoded_jwt = jwt.encode({'username': username, 'user_id': str(user['_id'])}, settings.SECRET_KEY, algorithm='HS256')
                return JsonResponse({'token': encoded_jwt, 'message': 'Login successful'})
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
            auth_header = request.headers.get('Authorization')
            if not auth_header or ' ' not in auth_header:
                return JsonResponse({'error': 'Authorization header missing or not formatted correctly'}, status=400)
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            if 'user_id' not in payload:
                return JsonResponse({'error': 'Invalid token payload'}, status=400)
            user_id = payload['user_id']
            username = payload['username']
            if 'shp_file' not in request.FILES or 'dbf_file' not in request.FILES:
                return JsonResponse({'error': 'Both .shp and .dbf files must be uploaded'}, status=400)
            shp_file = request.FILES['shp_file']
            dbf_file = request.FILES['dbf_file']
            # Create a new document in the MongoDB collection for the uploaded shapefile
            db = get_mongo_database()
            shapefiles_collection = db.shapefiles
            # Create a GridFS instance for storing the shapefile data
            fs = GridFS(db, collection='shapefile_data')
            # Store the .shp file in GridFS
            shp_file_id = fs.put(shp_file.file, filename=shp_file.name, content_type=shp_file.content_type)
            # Store the .dbf file in GridFS
            dbf_file_id = fs.put(dbf_file.file, filename=dbf_file.name, content_type=dbf_file.content_type)
            # Saving file metadata to MongoDB, including the GridFS file IDs
            shapefile_document = {
                'user_id': user_id,
                'username': username,
                'shp_filename': shp_file.name,
                'dbf_filename': dbf_file.name,
                'shp_gridfs_id': shp_file_id,
                'dbf_gridfs_id': dbf_file_id,
                'uploaded_at': datetime.now(),
                # Include additional metadata as necessary
            }
            # Insert the document into the collection
            shapefiles_collection.insert_one(shapefile_document)
            return JsonResponse({'message': 'Shapefile uploaded successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

# Endpoint to list user's shapefiles with download and view URLs
@csrf_exempt
def user_shapefiles(request):
    if request.method == 'GET':
        try:
            # Extract the token from the request headers
            auth_header = request.headers.get('Authorization')
            if not auth_header or ' ' not in auth_header:
                return JsonResponse({'error': 'Authorization header missing or not formatted correctly'}, status=400)
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            if 'user_id' not in payload:
                return JsonResponse({'error': 'Invalid token payload'}, status=400)
            user_id = payload['user_id']
            # Query MongoDB collection for shapefiles associated with the user
            db = get_mongo_database()
            shapefiles_collection = db.shapefiles
            user_shapefiles = shapefiles_collection.find({'user_id': user_id})
            shapefiles_data = []
            for sf in user_shapefiles:
                # Create the response JSON data with download and view URLs
                shapefile_info = {
                    'id': str(sf['_id']),
                    'filename': sf['shp_filename'],
                    # 'content_type': sf['content_type'],
                    'uploaded_at': sf['uploaded_at'],
                    'download_url': f'/download_shapefile/{str(sf["_id"])}',  # Add a download endpoint
                    'view_url': f'/view_shapefile/{str(sf["_id"])}',  # Add a view endpoint
                }

                shapefiles_data.append(shapefile_info)
            return JsonResponse({'shapefiles': shapefiles_data}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

@csrf_exempt
def view_shapefile(request, shapefile_id):
    try:
        # Query MongoDB collection for the specific shapefile by its ID
        db = get_mongo_database()
        shapefiles_collection = db.shapefiles
        sf = shapefiles_collection.find_one({'_id': ObjectId(shapefile_id)})
        if sf:
            # Read the shapefile data using the GridFS file ID
            fs = GridFS(db, collection='shapefile_data')
            shapefile_data = fs.get(ObjectId(sf['shp_gridfs_id'])).read()
            # Use the read_shapefile function to convert the shapefile data to GeoJSON
            geojson = read_shapefile(io.BytesIO(shapefile_data))
            # Create an HTTP response with the GeoJSON data
            response = JsonResponse({'data': geojson})
            return response
        else:
            return JsonResponse({'error': 'Shapefile not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Endpoint to download the shapefile
@csrf_exempt
def download_shapefile(request, shapefile_id):
    try:
        # Query MongoDB collection for the specific shapefile by its ID
        db = get_mongo_database()
        shapefiles_collection = db.shapefiles
        sf = shapefiles_collection.find_one({'_id': ObjectId(shapefile_id)})
        if sf:
            # Read the shapefile data using the GridFS file ID
            fs = GridFS(db, collection='shapefile_data')
            shapefile_data = fs.get(ObjectId(sf['shp_gridfs_id'])).read()
            # Create an HTTP response with the shapefile data as a file attachment
            response = HttpResponse(shapefile_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{sf["filename"]}"'
            return response
        else:
            return JsonResponse({'error': 'Shapefile not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
