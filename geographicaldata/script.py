import shapefile
import io

def read_shapefile(file_like):
    try:
        sf = shapefile.Reader(file_like)
        geojson = sf.__geo_interface__
        return geojson
    except Exception as e:
        return str(e)
