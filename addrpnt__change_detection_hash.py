import arcpy
import os
#import zip_loader
import re
import csv
# from hashlib import md5
from xxhash import xxh64


### to do: 
# add needed fields to comapre
# see if i can round the x,y values to avoid minor shifts in the points
# compare the hashes both ways, to look for adds and deletes ('hash1 in hash'2 and then 'hash2 in hash1')
# write out the uniqueids to a text file so we can join them to the data to show what has changed.


#_feature_class = 'D:\\AddressPoints\\ChangeDetections_Hashing\\hash_test.gdb\\base'
_feature_class = r'D:\AddressPoints\ChangeDetections_Hashing\zach_scripts\BoxElder\BoxElder.gdb\AddressPoints_BoxElder' 
_fields = ['AddNum', 'StreetName', 'UTAddPtID', 'PrefixDir']
#_pasthash = {} # pass this in if it's the fist time running this dataset, else, use the line below.
#_pasthash = 'D:\\AddressPoints\\ChangeDetections_Hashing\\hash.csv'
_outputHash = 'D:\\AddressPoints\\ChangeDetections_Hashing\\hash_BoxElderNew.csv'




def detect_addrpnt_changes(data_path, fields, past_hashes, output_hashes, shape_token=None):
    """Detect any changes and create a new hash store for uploading."""
    float_subber = re.compile(r'(\d+\.\d{4})(\d+)')
    hash_store = output_hashes
    cursor_fields = list(fields)
    print(cursor_fields)
    attribute_subindex = -1
    cursor_fields.append('OID@')
    if shape_token:
        cursor_fields.append('SHAPE@WKT')  # TODO: Use centriod SHAPE@XY coordinates for change mapping.
        cursor_fields.append(shape_token)
        attribute_subindex = -3

    hashes = {}
    changes = 0

    with arcpy.da.SearchCursor(data_path, cursor_fields) as cursor, \
            open(hash_store, 'wb') as hash_csv:
            hash_writer = csv.writer(hash_csv)
            # hash_writer.writerow(('hash',))
            hash_writer.writerow(('src_id', 'hash', 'AddNum', 'StreetName', 'PrefixDir'))
            for row in cursor:
                hasher = xxh64()  # Create/reset hash object
                hasher.update(float_subber.sub(r'\1', str(row[:attribute_subindex])))  # Hash only attributes
                if shape_token:
                    shape_string = row[-1]
                    if shape_string:  # None object won't hash
                        shape_string = float_subber.sub(r'\1', shape_string)
                        hasher.update(shape_string)
                    else:
                        hasher.update('No shape')  # Add something to the hash to represent None geometry object
                # Generate a unique hash if current row has duplicates
                digest = hasher.hexdigest()
                while digest in hashes:
                    hasher.update(digest)
                    digest = hasher.hexdigest()

                oid = row[attribute_subindex]
                # hash_writer.writerow((digest,))
                #hash_writer.writerow((oid, digest, str(row[-2])))
                hash_writer.writerow((oid, digest, str(row[0]), str(row[1]), str(row[3])))

                if digest not in past_hashes:
                    ## TODO: write these address points to a text file - then I can join this data to the fgdb and extract the address points that have had changes
                    print(str(row[2]))

                    changes += 1

    print 'Total changes: {}'.format(changes)

    return changes


# return past hash values from previous .csv file
def get_hash_lookup(hash_path, hash_field):
    """Get the has lookup for change detection."""
    hash_lookup = {}
    with arcpy.da.SearchCursor(hash_path, [hash_field]) as cursor:
        for row in cursor:
            hash_value = row[0]
            # hash_value, hash_oid = row
            if hash_value not in hash_lookup:
                hash_lookup[hash_value] = 0  # hash_oid isn't used for anything yet
            else:
                'Hash OID {} is duplicate wtf?'.format(hash_value)

    return hash_lookup


# write out the changes that were detected to a text file so we can join this to the feature classes
def write_changes_to_textfile():
    # maybe two columns in the text file - one to log what dataset (old or new data) and the other to log the the unique id value for the join 
    var = '' # dummy code until i write real code


# get past hash values
past_hash_store = 'D:\\AddressPoints\\ChangeDetections_Hashing\\hash_BoxElder.csv'
hash_field = 'hash'
past_hashes = get_hash_lookup(past_hash_store, hash_field)


# main function
if __name__ == '__main__':
    # detect changes in address points
    # first time though pass an empty dictionary {} for the pasthash value - and for the token use SHAPE@WKT
    #detect_addrpnt_changes(_feature_class,_fields, {}, _outputHash, 'SHAPE@WKT') # for first time - without previous hash
    detect_addrpnt_changes(_feature_class,_fields, past_hashes, _outputHash, 'SHAPE@WKT')
