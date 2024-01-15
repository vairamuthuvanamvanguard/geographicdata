import shapefile

def read_shapefile(shp_path):
    sf = shapefile.Reader(shp_path)
    geojson = sf.__geo_interface__
    return geojson
